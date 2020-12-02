// +build windows

package metrics

// TODO implement for Windows
func getCPUStats() (userCPU, systemCPU float64) {
	return 0.0, 0.0
}
