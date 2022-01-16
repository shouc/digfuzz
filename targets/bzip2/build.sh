git clone https://github.com/libigl/libigl.git target
pushd target
mkdir build
pushd build
cmake -DLIBIGL_WITH_OPENGL=OFF \
      -DLIBIGL_WITH_OPENGL_GLFW=OFF \
      -DLIBIGL_WITH_OPENGL_GLFW_IMGUI=OFF \
      -DLIBIGL_WITH_COMISO=OFF \
      -DLIBIGL_WITH_EMBREE=OFF \
      -DLIBIGL_WITH_PNG=OFF \
      -DLIBIGL_WITH_TETGEN=OFF \
      -DLIBIGL_WITH_TRIANGLE=OFF \
      -DLIBIGL_WITH_PREDICATES=OFF \
      -DLIBIGL_WITH_XML=OFF \
      -DLIBIGL_BUILD_TESTS=OFF \
      ..
CXXFLAGS=-no-pie make -j$(nproc)
popd

g++ -no-pie make -DIGL_STATIC_LIBRARY \
     -I./include \
     -isystem ./include \
     -isystem ./external/eigen \
     -c ../fuzz.cc -o fuzzer.o

g++ -no-pie fuzzer.o ./build/libigl.a ../../../driver.o -o harness
