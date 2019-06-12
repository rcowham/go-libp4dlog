// Copyright 2016-2018 The grok_exporter Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/fstab/grok_exporter/config"
	"github.com/fstab/grok_exporter/config/v2"
	"github.com/fstab/grok_exporter/tailer"
	"github.com/fstab/grok_exporter/tailer/fswatcher"
	"github.com/fstab/grok_exporter/tailer/glob"

	"github.com/sirupsen/logrus"
)

var (
	configPath = flag.String("config", "", "Path to the config file. Try '-config ./example/config.yml' to get started.")
	showConfig = flag.Bool("showconfig", false, "Print the current configuration to the console. Example: 'tailer -showconfig -config ./example/config.yml'")
)

func main() {
	flag.Parse()
	validateCommandLineOrExit()
	cfg, warn, err := config.LoadConfigFile(*configPath)
	if len(warn) > 0 && !*showConfig {
		// warning is suppressed when '-showconfig' is used
		fmt.Fprintf(os.Stderr, "%v\n", warn)
	}
	exitOnError(err)
	if *showConfig {
		fmt.Printf("%v\n", cfg)
		return
	}

	tail, err := startTailer(cfg)
	exitOnError(err)

	for {
		select {
		case err := <-tail.Errors():
			if os.IsNotExist(err.Cause()) {
				exitOnError(fmt.Errorf("error reading log lines: %v: use 'fail_on_missing_logfile: false' in the input configuration if you want grok_exporter to start even though the logfile is missing", err))
			} else {
				exitOnError(fmt.Errorf("error reading log lines: %v", err.Error()))
			}
		case line := <-tail.Lines():
			fmt.Fprintf(os.Stdout, "%v\n", line.Line)
		}
	}
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err.Error())
		os.Exit(-1)
	}
}

func validateCommandLineOrExit() {
	if len(*configPath) == 0 {
		if *showConfig {
			fmt.Fprint(os.Stderr, "Usage: tailer -showconfig -config <path>\n")
		} else {
			fmt.Fprint(os.Stderr, "Usage: tailer -config <path>\n")
		}
		os.Exit(-1)
	}
}

func startTailer(cfg *v2.Config) (fswatcher.FileTailer, error) {
	logger := logrus.New()
	logger.Level = logrus.WarnLevel
	var tail fswatcher.FileTailer
	g, err := glob.FromPath(cfg.Input.Path)
	if err != nil {
		return nil, err
	}
	switch {
	case cfg.Input.Type == "file":
		if cfg.Input.PollInterval == 0 {
			tail, err = fswatcher.RunFileTailer([]glob.Glob{g}, cfg.Input.Readall, cfg.Input.FailOnMissingLogfile, logger)
		} else {
			tail, err = fswatcher.RunPollingFileTailer([]glob.Glob{g}, cfg.Input.Readall, cfg.Input.FailOnMissingLogfile, cfg.Input.PollInterval, logger)
		}
	case cfg.Input.Type == "stdin":
		tail = tailer.RunStdinTailer()
	case cfg.Input.Type == "webhook":
		tail = tailer.InitWebhookTailer(&cfg.Input)
	default:
		return nil, fmt.Errorf("Config error: Input type '%v' unknown.", cfg.Input.Type)
	}
	// bufferLoadMetric := exporter.NewBufferLoadMetric(logger, cfg.Input.MaxLinesInBuffer > 0)
	// return tailer.BufferedTailerWithMetrics(tail, bufferLoadMetric, logger, cfg.Input.MaxLinesInBuffer), nil
	return tail, nil
}
