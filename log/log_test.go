/**********************************************
** @Des:
** @Author: liuzhiwang@xunlei.com
** @Last Modified time: 2020/4/30 下午5:39
***********************************************/

package log

import (
	"context"
	"errors"
	"github.com/741369/go_utils/log"
	"testing"
)

func init() {
	passLagerCfg := log.PassLagerCfg{
		Writers:        "file,stdout",
		LoggerLevel:    "DEBUG",
		LoggerFile:     "logs/test.log",
		LogFormatText:  true,
		RollingPolicy:  "size",
		LogRotateDate:  1,
		LogRotateSize:  10,
		LogBackupCount: 3,
	}
	log.InitWithConfig(&passLagerCfg)
}

func TestDebugf2(t *testing.T) {

	ctx := context.Background()
	ctx.Value()

	err := errors.New("new error")
	log.Debug(nil, "debug", map[string]interface{}{"debug": "123"})
	log.Debugf(nil, "%s", "21321")
	log.Info(nil, "info", map[string]interface{}{"test": 123})
	log.Infof(nil, "%s", "21321")
	log.Warn(nil, "warn")
	log.Warnf(nil, "%s", "warn   ====")
	log.Error(nil, "error", err, map[string]interface{}{"error": 123})
	log.Errorf(nil, err, "%v", map[string]interface{}{"error": 123})
	//log.Fatal(nil, "fatal", err)
	//log.Fatalf(nil, err, "%s", "fatal")
}
