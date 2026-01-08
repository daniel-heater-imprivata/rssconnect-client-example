set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

all: build

preset := if os() == "windows" { "conan-default" } else { "conan-release" }
build:
    conan install . --output-folder=build --build=missing -s build_type=Release
    cmake --preset {{preset}}
    cmake --build --preset conan-release

clean:
    cmake -E rm -rf build

format:
    find . -type f -name "*.h" -o -name "*.c" -o -name "*.cpp" -o -name "*.mm" | xargs clang-format -i
    find . -type f -name "CMakeLists.txt" | xargs cmake-format -i

[windows]
run-example api_id=env_var_or_default('PAS_API_ID', ''): build
    {{ if api_id == '' { error("API ID not provided. Set PAS_API_ID or pass as parameter: just test-example <api-id>") } else { "" } }}
    @echo "Using API ID: {{api_id}}"
    $env:PATH = "$env:LIBRSSCONNECT_DIR\bin;$env:PATH" ; .\build\conanrun.bat ; .\build\Release\reference_app.exe {{api_id}}

[unix]
run-example api_id=env_var_or_default('PAS_API_ID', ''): build
    {{ if api_id == '' { error("API ID not provided. Set PAS_API_ID or pass as parameter: just test-example <api-id>") } else { "" } }}
    @echo "Using API ID: {{api_id}}"
    ./build/reference_app {{api_id}}

