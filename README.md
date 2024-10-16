# ps4

Playstation 4 pacakge manger (ps4) is a package manager  built for jaguarlinux or any other linux distro ,

## Building

The preferred build system for building ps4 is Meson:

```
# meson setup -Dprefix=/ build
# ninja -C build
# meson install -C build
```

For bootstrapping without Python, muon is also compatible. All you have to do is replace `meson` with `muon` in the above example.

To build a static ps4, pass the right arguments to the above commands:

```
# meson setup -Dc_link_args="-static" -Dprefer_static=true -Ddefault_library=static build
# ninja -C build src/ps4
```

Which will give you a `./build/src/ps4` that is statically linked.
or you can build using a make file 

## Documentation

Online documentation is available in the [doc/](doc/) directory in the form of man pages.

The [ps4(8)](doc/ps4.8.scd) man page provides a basic overview of the package management
system.


The main reason why i built this package manager is to make my distro unqiue and the reson why i fork the apk packagemangaer becuse it's easy and have alot of commands argment you can do i want to keep on maintaining the this package manger i want my distro to be kinda unique and i am just doing this project for fun  donateing can be optinal but will help out 
