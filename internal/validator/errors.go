package validator

// ValidationError separates a safe public message (sent to callers) from the
// full internal detail (available for server-side logging via Unwrap).
type ValidationError struct {
	Public   string
	Internal error
}

func (e *ValidationError) Error() string { return e.Public }
func (e *ValidationError) Unwrap() error { return e.Internal }
