package bundles

import "time"

// SetRetryInterval shortens the retry interval for a test and restores it after.
func SetRetryInterval(d time.Duration) (restore func()) {
	old := RetryInterval
	RetryInterval = d
	return func() { RetryInterval = old }
}
