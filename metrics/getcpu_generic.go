// +build !windows

package metrics

import (
	"syscall"
)

func getCPUStats() (userCPU, systemCPU float64) {

	var r syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &r) == nil {
		return float64(r.Utime.Nano()) / 1e9, float64(r.Stime.Nano()) / 1e9
	}
	return 0.0, 0.0
}
