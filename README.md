TCLib
=====

TrueCrypt and VeraCrypt block device library with integrated crypto and tools

# Building

It's a Maven project.

You need [BaseLib](https://github.com/mchahn/baselib), just build it locally, afterwards this project, using the same commands:

```
mvn package
mvn install # -Dmaven.test.skip=true
```

# Running

In VScode simply launch the include apps set up in _vscode_launch.json_.
