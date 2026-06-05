Output demo.gif

Set Width 1200
Set Height 750
Set FontSize 12
Set Theme "Dracula"
Set TypingSpeed 80ms
Set PlaybackSpeed 1.0

# Show the scan
Type "sentinel scan ./tests/fixtures/vault-vulnerable"
Sleep 500ms
Enter
Sleep 6s

# Clear and show rules list
Type "clear"
Enter
Sleep 300ms
Type "sentinel rules"
Sleep 500ms
Enter
Sleep 3s
