package challenger

const StandaloneDebugReadme = `
The original troubleshooting workflow used "go run challenger/standalone_debug.go".
The executable now lives in challenger/debug_tools/standalone_debug.go to avoid
mixing packages inside this directory.

Run:
  cd challenger/debug_tools && go run standalone_debug.go
`
