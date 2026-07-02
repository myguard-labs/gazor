module github.com/myguard-labs/gazor

go 1.24

// Versions v1.0.0–v1.1.0 were published under the old module path
// github.com/eilandert/gazor. Under the new path they are invalid.
retract (
	v1.1.0
	v1.0.0
)
