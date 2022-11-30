Output docs/assets/cmake_demo.gif

Require cifuzz
Require cmake
Require awk

Set FontSize 14
Set Width 1200
Set Height 600

Sleep 500ms

Type "echo This is the cifuzz CMake demo"
Enter

Hide

Type "cd examples/cmake"
Enter

Show

Sleep 1s

Type "cifuzz run my_fuzz_test"
Enter

Sleep 5s

Type "cifuzz findings"
Enter 

Sleep 2s

Type "cifuzz finding `cifuzz findings | head -n1 | awk '{print $1}'`"
Enter

Sleep 5s

Type "cifuzz coverage my_fuzz_test"
Enter

Sleep 5s
