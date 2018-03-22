// Copyright 2016 The Hugo Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package commands defines and implements command-line commands and flags
// used by Hugo. Commands and flags are implemented using Cobra.
package commands

import (
	"fmt"
	"io/ioutil"
	"os/signal"
	"sort"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	src "github.com/gohugoio/hugo/source"

	"github.com/gohugoio/hugo/config"

	"github.com/gohugoio/hugo/parser"
	flag "github.com/spf13/pflag"

	"regexp"

	"github.com/gohugoio/hugo/helpers"
	"github.com/gohugoio/hugo/hugolib"
	"github.com/gohugoio/hugo/livereload"
	"github.com/gohugoio/hugo/utils"
	"github.com/gohugoio/hugo/watcher"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/fsync"
	jww "github.com/spf13/jwalterweatherman"
	"github.com/spf13/nitro"
)

println("test")

// Hugo represents the Hugo sites to build. This variable is exported as it
// is used by at least one external library (the Hugo caddy plugin). We should
// provide a cleaner external API, but until then, this is it.
var Hugo *hugolib.HugoSites

const (
	ansiEsc    = "\u001B"
	clearLine  = "\r\033[K"
	hideCursor = ansiEsc + "[?25l"
	showCursor = ansiEsc + "[?25h"
)

// Reset resets Hugo ready for a new full build. This is mainly only useful
// for benchmark testing etc. via the CLI commands.
func Reset() error {
	Hugo = nil
	return nil
}

// commandError is an error used to signal different error situations in command handling.
type commandError struct {
	s         string
	userError bool
}

func (c commandError) Error() string {
	return c.s
}

func (c commandError) isUserError() bool {
	return c.userError
}

func newUserError(a ...interface{}) commandError {
	return commandError{s: fmt.Sprintln(a...), userError: true}
}

func newSystemError(a ...interface{}) commandError {
	return commandError{s: fmt.Sprintln(a...), userError: false}
}

func newSystemErrorF(format string, a ...interface{}) commandError {
	return commandError{s: fmt.Sprintf(format, a...), userError: false}
}

// Catch some of the obvious user errors from Cobra.
// We don't want to show the usage message for every error.
// The below may be to generic. Time will show.
var userErrorRegexp = regexp.MustCompile("argument|flag|shorthand")

func isUserError(err error) bool {
	if cErr, ok := err.(commandError); ok && cErr.isUserError() {
		return true
	}

	return userErrorRegexp.MatchString(err.Error())
}

// HugoCmd is Hugo's root command.
// Every other command attached to HugoCmd is a child command to it.
var HugoCmd = &cobra.Command{
	Use:   "hugo",
	Short: "hugo builds your site",
	Long: `hugo is the main command, used to build your Hugo site.

Hugo is a Fast and Flexible Static Site Generator
built with love by spf13 and friends in Go.

Complete documentation is available at http://gohugo.io/.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		cfgInit := func(c *commandeer) error {
			if buildWatch {
				c.Set("disableLiveReload", true)
			}
			c.Set("renderToMemory", renderToMemory)
			return nil
		}

		c, err := InitializeConfig(buildWatch, cfgInit)
		if err != nil {
			return err
		}

		return c.build()
	},
}

var hugoCmdV *cobra.Command

// Flags that are to be added to commands.
var (
	buildWatch     bool
	logging        bool
	renderToMemory bool // for benchmark testing
	verbose        bool
	verboseLog     bool
	debug          bool
	quiet          bool
)

var (
	gc              bool
	baseURL         string
	cacheDir        string
	contentDir      string
	layoutDir       string
	cfgFile         string
	destination     string
	logFile         string
	theme           string
	themesDir       string
	source          string
	logI18nWarnings bool
	disableKinds    []string
)

// Execute adds all child commands to the root command HugoCmd and sets flags appropriately.
func Execute() {
	HugoCmd.SetGlobalNormalizationFunc(helpers.NormalizeHugoFlags)

	HugoCmd.SilenceUsage = true

	AddCommands()

	if c, err := HugoCmd.ExecuteC(); err != nil {
		if isUserError(err) {
			c.Println("")
			c.Println(c.UsageString())
		}

		os.Exit(-1)
	}
}

// AddCommands adds child commands to the root command HugoCmd.
func AddCommands() {
	HugoCmd.AddCommand(serverCmd)
	HugoCmd.AddCommand(versionCmd)
	HugoCmd.AddCommand(envCmd)
	HugoCmd.AddCommand(configCmd)
	HugoCmd.AddCommand(checkCmd)
	HugoCmd.AddCommand(benchmarkCmd)
	HugoCmd.AddCommand(convertCmd)
	HugoCmd.AddCommand(newCmd)
	HugoCmd.AddCommand(listCmd)
	HugoCmd.AddCommand(importCmd)

	HugoCmd.AddCommand(genCmd)
	genCmd.AddCommand(genautocompleteCmd)
	genCmd.AddCommand(gendocCmd)
	genCmd.AddCommand(genmanCmd)
	genCmd.AddCommand(createGenDocsHelper().cmd)
	genCmd.AddCommand(createGenChromaStyles().cmd)

}

// initHugoBuilderFlags initializes all common flags, typically used by the
// core build commands, namely hugo itself, server, check and benchmark.
func initHugoBuilderFlags(cmd *cobra.Command) {
	initHugoBuildCommonFlags(cmd)
}

func initRootPersistentFlags() {
	HugoCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is path/config.yaml|json|toml)")
	HugoCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "build in quiet mode")

	// Set bash-completion
	validConfigFilenames := []string{"json", "js", "yaml", "yml", "toml", "tml"}
	_ = HugoCmd.PersistentFlags().SetAnnotation("config", cobra.BashCompFilenameExt, validConfigFilenames)
}

// initHugoBuildCommonFlags initialize common flags related to the Hugo build.
// Called by initHugoBuilderFlags.
func initHugoBuildCommonFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("cleanDestinationDir", false, "remove files from destination not found in static directories")
	cmd.Flags().BoolP("buildDrafts", "D", false, "include content marked as draft")
	cmd.Flags().BoolP("buildFuture", "F", false, "include content with publishdate in the future")
	cmd.Flags().BoolP("buildExpired", "E", false, "include expired content")
	cmd.Flags().StringVarP(&source, "source", "s", "", "filesystem path to read files relative from")
	cmd.Flags().StringVarP(&contentDir, "contentDir", "c", "", "filesystem path to content directory")
	cmd.Flags().StringVarP(&layoutDir, "layoutDir", "l", "", "filesystem path to layout directory")
	cmd.Flags().StringVarP(&cacheDir, "cacheDir", "", "", "filesystem path to cache directory. Defaults: $TMPDIR/hugo_cache/")
	cmd.Flags().BoolP("ignoreCache", "", false, "ignores the cache directory")
	cmd.Flags().StringVarP(&destination, "destination", "d", "", "filesystem path to write files to")
	cmd.Flags().StringVarP(&theme, "theme", "t", "", "theme to use (located in /themes/THEMENAME/)")
	cmd.Flags().StringVarP(&themesDir, "themesDir", "", "", "filesystem path to themes directory")
	cmd.Flags().Bool("uglyURLs", false, "(deprecated) if true, use /filename.html instead of /filename/")
	cmd.Flags().Bool("canonifyURLs", false, "(deprecated) if true, all relative URLs will be canonicalized using baseURL")
	cmd.Flags().StringVarP(&baseURL, "baseURL", "b", "", "hostname (and path) to the root, e.g. http://spf13.com/")
	cmd.Flags().Bool("enableGitInfo", false, "add Git revision, date and author info to the pages")
	cmd.Flags().BoolVar(&gc, "gc", false, "enable to run some cleanup tasks (remove unused cache files) after the build")

	cmd.Flags().BoolVar(&nitro.AnalysisOn, "stepAnalysis", false, "display memory and timing of different steps of the program")
	cmd.Flags().Bool("templateMetrics", false, "display metrics about template executions")
	cmd.Flags().Bool("templateMetricsHints", false, "calculate some improvement hints when combined with --templateMetrics")
	cmd.Flags().Bool("pluralizeListTitles", true, "(deprecated) pluralize titles in lists using inflect")
	cmd.Flags().Bool("preserveTaxonomyNames", false, `(deprecated) preserve taxonomy names as written ("Gérard Depardieu" vs "gerard-depardieu")`)
	cmd.Flags().BoolP("forceSyncStatic", "", false, "copy all files when static is changed.")
	cmd.Flags().BoolP("noTimes", "", false, "don't sync modification time of files")
	cmd.Flags().BoolP("noChmod", "", false, "don't sync permission mode of files")
	cmd.Flags().BoolVarP(&logI18nWarnings, "i18n-warnings", "", false, "print missing translations")

	cmd.Flags().StringSliceVar(&disableKinds, "disableKinds", []string{}, "disable different kind of pages (home, RSS etc.)")

	// Set bash-completion.
	// Each flag must first be defined before using the SetAnnotation() call.
	_ = cmd.Flags().SetAnnotation("source", cobra.BashCompSubdirsInDir, []string{})
	_ = cmd.Flags().SetAnnotation("cacheDir", cobra.BashCompSubdirsInDir, []string{})
	_ = cmd.Flags().SetAnnotation("destination", cobra.BashCompSubdirsInDir, []string{})
	_ = cmd.Flags().SetAnnotation("theme", cobra.BashCompSubdirsInDir, []string{"themes"})
}

func initBenchmarkBuildingFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&renderToMemory, "renderToMemory", false, "render to memory (only useful for benchmark testing)")
}

// init initializes flags.
func init() {
	HugoCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	HugoCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "debug output")
	HugoCmd.PersistentFlags().BoolVar(&logging, "log", false, "enable Logging")
	HugoCmd.PersistentFlags().StringVar(&logFile, "logFile", "", "log File path (if set, logging enabled automatically)")
	HugoCmd.PersistentFlags().BoolVar(&verboseLog, "verboseLog", false, "verbose logging")

	initRootPersistentFlags()
	initHugoBuilderFlags(HugoCmd)
	initBenchmarkBuildingFlags(HugoCmd)

	HugoCmd.Flags().BoolVarP(&buildWatch, "watch", "w", false, "watch filesystem for changes and recreate as needed")
	hugoCmdV = HugoCmd

	// Set bash-completion
	_ = HugoCmd.PersistentFlags().SetAnnotation("logFile", cobra.BashCompFilenameExt, []string{})
}

// InitializeConfig initializes a config file with sensible default configuration flags.
func InitializeConfig(running bool, doWithCommandeer func(c *commandeer) error, subCmdVs ...*cobra.Command) (*commandeer, error) {

	c, err := newCommandeer(running, doWithCommandeer, subCmdVs...)
	if err != nil {
		return nil, err
	}

	return c, nil

}

func createLogger(cfg config.Provider) (*jww.Notepad, error) {
	var (
		logHandle       = ioutil.Discard
		logThreshold    = jww.LevelWarn
		logFile         = cfg.GetString("logFile")
		outHandle       = os.Stdout
		stdoutThreshold = jww.LevelError
	)

	if verboseLog || logging || (logFile != "") {
		var err error
		if logFile != "" {
			logHandle, err = os.OpenFile(logFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
			if err != nil {
				return nil, newSystemError("Failed to open log file:", logFile, err)
			}
		} else {
			logHandle, err = ioutil.TempFile("", "hugo")
			if err != nil {
				return nil, newSystemError(err)
			}
		}
	} else if !quiet && cfg.GetBool("verbose") {
		stdoutThreshold = jww.LevelInfo
	}

	if cfg.GetBool("debug") {
		stdoutThreshold = jww.LevelDebug
	}

	if verboseLog {
		logThreshold = jww.LevelInfo
		if cfg.GetBool("debug") {
			logThreshold = jww.LevelDebug
		}
	}

	// The global logger is used in some few cases.
	jww.SetLogOutput(logHandle)
	jww.SetLogThreshold(logThreshold)
	jww.SetStdoutThreshold(stdoutThreshold)
	helpers.InitLoggers()

	return jww.NewNotepad(stdoutThreshold, logThreshold, outHandle, logHandle, "", log.Ldate|log.Ltime), nil
}

func (c *commandeer) initializeFlags(cmd *cobra.Command) {
	persFlagKeys := []string{"debug", "verbose", "logFile"}
	flagKeys := []string{
		"cleanDestinationDir",
		"buildDrafts",
		"buildFuture",
		"buildExpired",
		"uglyURLs",
		"canonifyURLs",
		"enableRobotsTXT",
		"enableGitInfo",
		"pluralizeListTitles",
		"preserveTaxonomyNames",
		"ignoreCache",
		"forceSyncStatic",
		"noTimes",
		"noChmod",
		"templateMetrics",
		"templateMetricsHints",
	}

	for _, key := range persFlagKeys {
		c.setValueFromFlag(cmd.PersistentFlags(), key)
	}
	for _, key := range flagKeys {
		c.setValueFromFlag(cmd.Flags(), key)
	}

}

var deprecatedFlags = map[string]bool{
	strings.ToLower("uglyURLs"):              true,
	strings.ToLower("pluralizeListTitles"):   true,
	strings.ToLower("preserveTaxonomyNames"): true,
	strings.ToLower("canonifyURLs"):          true,
}

func (c *commandeer) setValueFromFlag(flags *flag.FlagSet, key string) {
	if flags.Changed(key) {
		if _, deprecated := deprecatedFlags[strings.ToLower(key)]; deprecated {
			msg := fmt.Sprintf(`Set "%s = true" in your config.toml.
If you need to set this configuration value from the command line, set it via an OS environment variable: "HUGO_%s=true hugo"`, key, strings.ToUpper(key))
			// Remove in Hugo 0.38
			helpers.Deprecated("hugo", "--"+key+" flag", msg, true)
		}
		f := flags.Lookup(key)
		c.Set(key, f.Value.String())
	}
}

func (c *commandeer) fullBuild() error {
	var (
		g         errgroup.Group
		langCount map[string]uint64
	)

	if !quiet {
		fmt.Print(hideCursor + "Building sites … ")
		defer func() {
			fmt.Print(showCursor + clearLine)
		}()
	}

	copyStaticFunc := func() error {
		cnt, err := c.copyStatic()
		if err != nil {
			return fmt.Errorf("Error copying static files: %s", err)
		}
		langCount = cnt
		return nil
	}
	buildSitesFunc := func() error {
		if err := c.buildSites(); err != nil {
			return fmt.Errorf("Error building site: %s", err)
		}
		return nil
	}
	// Do not copy static files and build sites in parallel if cleanDestinationDir is enabled.
	// This flag deletes all static resources in /public folder that are missing in /static,
	// and it does so at the end of copyStatic() call.
	if c.Cfg.GetBool("cleanDestinationDir") {
		if err := copyStaticFunc(); err != nil {
			return err
		}
		if err := buildSitesFunc(); err != nil {
			return err
		}
	} else {
		g.Go(copyStaticFunc)
		g.Go(buildSitesFunc)
		if err := g.Wait(); err != nil {
			return err
		}
	}

	for _, s := range Hugo.Sites {
		s.ProcessingStats.Static = langCount[s.Language.Lang]
	}

	if gc {
		count, err := Hugo.GC()
		if err != nil {
			return err
		}
		for _, s := range Hugo.Sites {
			// We have no way of knowing what site the garbage belonged to.
			s.ProcessingStats.Cleaned = uint64(count)
		}
	}

	return nil

}

func (c *commandeer) build() error {
	defer c.timeTrack(time.Now(), "Total")

	if err := c.fullBuild(); err != nil {
		return err
	}

	// TODO(bep) Feedback?
	if !quiet {
		fmt.Println()
		Hugo.PrintProcessingStats(os.Stdout)
		fmt.Println()
	}

	if buildWatch {
		watchDirs, err := c.getDirList()
		if err != nil {
			return err
		}
		c.Logger.FEEDBACK.Println("Watching for changes in", c.PathSpec().AbsPathify(c.Cfg.GetString("contentDir")))
		c.Logger.FEEDBACK.Println("Press Ctrl+C to stop")
		watcher, err := c.newWatcher(watchDirs...)
		utils.CheckErr(c.Logger, err)
		defer watcher.Close()

		<-sigs
	}

	return nil
}

func (c *commandeer) serverBuild() error {
	defer c.timeTrack(time.Now(), "Total")

	if err := c.fullBuild(); err != nil {
		return err
	}

	// TODO(bep) Feedback?
	if !quiet {
		fmt.Println()
		Hugo.PrintProcessingStats(os.Stdout)
		fmt.Println()
	}

	return nil
}

func (c *commandeer) copyStatic() (map[string]uint64, error) {
	return c.doWithPublishDirs(c.copyStaticTo)
}

func (c *commandeer) createStaticDirsConfig() ([]*src.Dirs, error) {
	var dirsConfig []*src.Dirs

	if !c.languages.IsMultihost() {
		dirs, err := src.NewDirs(c.Fs, c.Cfg, c.DepsCfg.Logger)
		if err != nil {
			return nil, err
		}
		dirsConfig = append(dirsConfig, dirs)
	} else {
		for _, l := range c.languages {
			dirs, err := src.NewDirs(c.Fs, l, c.DepsCfg.Logger)
			if err != nil {
				return nil, err
			}
			dirsConfig = append(dirsConfig, dirs)
		}
	}

	return dirsConfig, nil

}

func (c *commandeer) doWithPublishDirs(f func(dirs *src.Dirs, publishDir string) (uint64, error)) (map[string]uint64, error) {

	langCount := make(map[string]uint64)

	for _, dirs := range c.staticDirsConfig {

		cnt, err := f(dirs, c.pathSpec.PublishDir)
		if err != nil {
			return langCount, err
		}

		if dirs.Language == nil {
			// Not multihost
			for _, l := range c.languages {
				langCount[l.Lang] = cnt
			}
		} else {
			langCount[dirs.Language.Lang] = cnt
		}

	}

	return langCount, nil
}

type countingStatFs struct {
	afero.Fs
	statCounter uint64
}

func (fs *countingStatFs) Stat(name string) (os.FileInfo, error) {
	f, err := fs.Fs.Stat(name)
	if err == nil {
		if !f.IsDir() {
			atomic.AddUint64(&fs.statCounter, 1)
		}
	}
	return f, err
}

func (c *commandeer) copyStaticTo(dirs *src.Dirs, publishDir string) (uint64, error) {

	// If root, remove the second '/'
	if publishDir == "//" {
		publishDir = helpers.FilePathSeparator
	}

	if dirs.Language != nil {
		// Multihost setup.
		publishDir = filepath.Join(publishDir, dirs.Language.Lang)
	}

	staticSourceFs, err := dirs.CreateStaticFs()
	if err != nil {
		return 0, err
	}

	if staticSourceFs == nil {
		c.Logger.WARN.Println("No static directories found to sync")
		return 0, nil
	}

	fs := &countingStatFs{Fs: staticSourceFs}

	syncer := fsync.NewSyncer()
	syncer.NoTimes = c.Cfg.GetBool("noTimes")
	syncer.NoChmod = c.Cfg.GetBool("noChmod")
	syncer.SrcFs = fs
	syncer.DestFs = c.Fs.Destination
	// Now that we are using a unionFs for the static directories
	// We can effectively clean the publishDir on initial sync
	syncer.Delete = c.Cfg.GetBool("cleanDestinationDir")

	if syncer.Delete {
		c.Logger.INFO.Println("removing all files from destination that don't exist in static dirs")

		syncer.DeleteFilter = func(f os.FileInfo) bool {
			return f.IsDir() && strings.HasPrefix(f.Name(), ".")
		}
	}
	c.Logger.INFO.Println("syncing static files to", publishDir)

	// because we are using a baseFs (to get the union right).
	// set sync src to root
	err = syncer.Sync(publishDir, helpers.FilePathSeparator)
	if err != nil {
		return 0, err
	}

	// Sync runs Stat 3 times for every source file (which sounds much)
	numFiles := fs.statCounter / 3

	return numFiles, err
}

func (c *commandeer) timeTrack(start time.Time, name string) {
	if quiet {
		return
	}
	elapsed := time.Since(start)
	c.Logger.FEEDBACK.Printf("%s in %v ms", name, int(1000*elapsed.Seconds()))
}

// getDirList provides NewWatcher() with a list of directories to watch for changes.
func (c *commandeer) getDirList() ([]string, error) {
	var a []string

	// To handle nested symlinked content dirs
	var seen = make(map[string]bool)
	var nested []string

	dataDir := c.PathSpec().AbsPathify(c.Cfg.GetString("dataDir"))
	i18nDir := c.PathSpec().AbsPathify(c.Cfg.GetString("i18nDir"))
	staticSyncer, err := newStaticSyncer(c)
	if err != nil {
		return nil, err
	}

	layoutDir := c.PathSpec().GetLayoutDirPath()
	staticDirs := staticSyncer.d.AbsStaticDirs

	newWalker := func(allowSymbolicDirs bool) func(path string, fi os.FileInfo, err error) error {
		return func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				if path == dataDir && os.IsNotExist(err) {
					c.Logger.WARN.Println("Skip dataDir:", err)
					return nil
				}

				if path == i18nDir && os.IsNotExist(err) {
					c.Logger.WARN.Println("Skip i18nDir:", err)
					return nil
				}

				if path == layoutDir && os.IsNotExist(err) {
					c.Logger.WARN.Println("Skip layoutDir:", err)
					return nil
				}

				if os.IsNotExist(err) {
					for _, staticDir := range staticDirs {
						if path == staticDir && os.IsNotExist(err) {
							c.Logger.WARN.Println("Skip staticDir:", err)
						}
					}
					// Ignore.
					return nil
				}

				c.Logger.ERROR.Println("Walker: ", err)
				return nil
			}

			// Skip .git directories.
			// Related to https://github.com/gohugoio/hugo/issues/3468.
			if fi.Name() == ".git" {
				return nil
			}

			if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
				link, err := filepath.EvalSymlinks(path)
				if err != nil {
					c.Logger.ERROR.Printf("Cannot read symbolic link '%s', error was: %s", path, err)
					return nil
				}
				linkfi, err := helpers.LstatIfOs(c.Fs.Source, link)
				if err != nil {
					c.Logger.ERROR.Printf("Cannot stat %q: %s", link, err)
					return nil
				}
				if !allowSymbolicDirs && !linkfi.Mode().IsRegular() {
					c.Logger.ERROR.Printf("Symbolic links for directories not supported, skipping %q", path)
					return nil
				}

				if allowSymbolicDirs && linkfi.IsDir() {
					// afero.Walk will not walk symbolic links, so wee need to do it.
					if !seen[path] {
						seen[path] = true
						nested = append(nested, path)
					}
					return nil
				}

				fi = linkfi
			}

			if fi.IsDir() {
				if fi.Name() == ".git" ||
					fi.Name() == "node_modules" || fi.Name() == "bower_components" {
					return filepath.SkipDir
				}
				a = append(a, path)
			}
			return nil
		}
	}

	symLinkWalker := newWalker(true)
	regularWalker := newWalker(false)

	// SymbolicWalk will log anny ERRORs
	_ = helpers.SymbolicWalk(c.Fs.Source, dataDir, regularWalker)
	_ = helpers.SymbolicWalk(c.Fs.Source, c.PathSpec().AbsPathify(c.Cfg.GetString("contentDir")), symLinkWalker)
	_ = helpers.SymbolicWalk(c.Fs.Source, i18nDir, regularWalker)
	_ = helpers.SymbolicWalk(c.Fs.Source, layoutDir, regularWalker)
	for _, staticDir := range staticDirs {
		_ = helpers.SymbolicWalk(c.Fs.Source, staticDir, regularWalker)
	}

	if c.PathSpec().ThemeSet() {
		themesDir := c.PathSpec().GetThemeDir()
		_ = helpers.SymbolicWalk(c.Fs.Source, filepath.Join(themesDir, "layouts"), regularWalker)
		_ = helpers.SymbolicWalk(c.Fs.Source, filepath.Join(themesDir, "i18n"), regularWalker)
		_ = helpers.SymbolicWalk(c.Fs.Source, filepath.Join(themesDir, "data"), regularWalker)
	}

	if len(nested) > 0 {
		for {

			toWalk := nested
			nested = nested[:0]

			for _, d := range toWalk {
				_ = helpers.SymbolicWalk(c.Fs.Source, d, symLinkWalker)
			}

			if len(nested) == 0 {
				break
			}
		}
	}

	a = helpers.UniqueStrings(a)
	sort.Strings(a)

	return a, nil
}

func (c *commandeer) recreateAndBuildSites(watching bool) (err error) {
	defer c.timeTrack(time.Now(), "Total")
	if err := c.initSites(); err != nil {
		return err
	}
	if !quiet {
		c.Logger.FEEDBACK.Println("Started building sites ...")
	}
	return Hugo.Build(hugolib.BuildCfg{CreateSitesFromConfig: true})
}

func (c *commandeer) resetAndBuildSites() (err error) {
	if err = c.initSites(); err != nil {
		return
	}
	if !quiet {
		c.Logger.FEEDBACK.Println("Started building sites ...")
	}
	return Hugo.Build(hugolib.BuildCfg{ResetState: true})
}

func (c *commandeer) initSites() error {
	if Hugo != nil {
		Hugo.Cfg = c.Cfg
		Hugo.Log.ResetLogCounters()
		return nil
	}
	h, err := hugolib.NewHugoSites(*c.DepsCfg)

	if err != nil {
		return err
	}
	Hugo = h

	return nil
}

func (c *commandeer) buildSites() (err error) {
	if err := c.initSites(); err != nil {
		return err
	}
	return Hugo.Build(hugolib.BuildCfg{})
}

func (c *commandeer) rebuildSites() error {
	defer c.timeTrack(time.Now(), "Total")

	if err := c.initSites(); err != nil {
		return err
	}
	visited := c.visitedURLs.PeekAllSet()
	doLiveReload := !buildWatch && !c.Cfg.GetBool("disableLiveReload")
	if doLiveReload && !c.Cfg.GetBool("disableFastRender") {

		// Make sure we always render the home pages
		for _, l := range c.languages {
			langPath := c.PathSpec().GetLangSubDir(l.Lang)
			if langPath != "" {
				langPath = langPath + "/"
			}
			home := c.pathSpec.PrependBasePath("/" + langPath)
			visited[home] = true
		}

	}
	return Hugo.Build(hugolib.BuildCfg{RecentlyVisited: visited}, events...)
}

// isThemeVsHugoVersionMismatch returns whether the current Hugo version is
// less than the theme's min_version.
func (c *commandeer) isThemeVsHugoVersionMismatch(fs afero.Fs) (mismatch bool, requiredMinVersion string) {
	if !c.PathSpec().ThemeSet() {
		return
	}

	themeDir := c.PathSpec().GetThemeDir()

	path := filepath.Join(themeDir, "theme.toml")

	exists, err := helpers.Exists(path, fs)

	if err != nil || !exists {
		return
	}

	b, err := afero.ReadFile(fs, path)

	tomlMeta, err := parser.HandleTOMLMetaData(b)

	if err != nil {
		return
	}

	if minVersion, ok := tomlMeta["min_version"]; ok {
		return helpers.CompareVersion(minVersion) > 0, fmt.Sprint(minVersion)
	}

	return
}
