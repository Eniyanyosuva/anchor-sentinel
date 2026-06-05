Output demo.gif

Set FontSize 14
Set Width 900
Set Height 600
Set Theme "Dracula"
Set PlaybackSpeed 1.0
Set TypingSpeed 80ms

# Show the scan
Type "sentinel scan ./tests/fixtures/vault-vulnerable"
Sleep 500ms
Enter
Sleep 5s

# Pause on the summary footer so viewer can read it
Sleep 2s

# Clear and show rules list
Type "clear"
Enter
Sleep 300ms
Type "sentinel rules"
Sleep 500ms
Enter
Sleep 3s
