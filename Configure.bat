@mkdir build-x86 >nul
pushd build-x86 >nul
cmake -G "Visual Studio 12" ..\Nettitude
popd >nul