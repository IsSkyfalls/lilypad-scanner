package log

import (
	"log"
	"os"
)

type FileLogger struct {
	logger *log.Logger
}

func (log *FileLogger) Log(s string) {
	log.logger.Println(s)
}

func (log *FileLogger) Logf(s string, args ...interface{}) {
	log.logger.Printf(s+"\n", args...)
}

func CreateLogger(name string) *FileLogger {
	logger := log.Logger{}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
	if err != nil {
		panic("failed to open file: " + err.Error())
	}
	logger.SetOutput(f)
	return &FileLogger{
		logger: &logger,
	}
}

func Debug() *FileLogger {
	return logDebug
}

func Info() *FileLogger {
	return logInfo
}

var (
	logDebug = CreateLogger("debug.log")
	logInfo  = CreateLogger("info.log")
)
