all: build

build:
    cmake -B build -G Ninja
    cmake --build build

clean:
    rm -rf build


# Test reference example with API ID (uses ~/.pas/config.json)
# Usage: just test-example [api-id]
# If api-id not provided, uses PAS_API_ID environment variable
[windows]
run-example api_id=env_var_or_default('PAS_API_ID', ''): build
    {{ if api_id == '' { error("API ID not provided. Set PAS_API_ID or pass as parameter: just test-example <api-id>") } else { "" } }}
    @echo "Using API ID: {{api_id}}"
    build\\{{build_type}}\reference_app.exe {{api_id}}

[unix]
run-example api_id=env_var_or_default('PAS_API_ID', ''): build
    {{ if api_id == '' { error("API ID not provided. Set PAS_API_ID or pass as parameter: just test-example <api-id>") } else { "" } }}
    @echo "Using API ID: {{api_id}}"
    ./build/reference_app {{api_id}}
