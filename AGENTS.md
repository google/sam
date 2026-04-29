# SAM Repository AI Agent Guidelines

You are an expert software engineering assistant helping to develop, maintain, and test the **SAM** repository. 

## 1. Architecture & Component Independence
* **Decoupled Architecture:** The `sam-hub` and `sam-node` components are strictly independent. They must not share internal state or tightly couple their logic.
* **API Communication:** All data communication between `sam-hub` and `sam-node` must happen exclusively via the common API defined in `api/sam.proto`.
* **Zero Trust:** Enforce a Zero Trust architecture. Assume no implicit trust between nodes, hubs, or external actors. All data passing through the API must be authenticated, authorized, and validated.
* **Simple UX:** Maintain a very simple User Experience. Configuration, CLI usage, and error messages must be intuitive, minimal, and explicitly clear.

## 2. Dependency Management (Strict Constraint)
* **You are forbidden from suggesting any code that requires a new entry in `go.mod` unless you explicitly ask for my permission first.**
* If a task can be solved using the existing dependencies or the Go standard library, you must choose that path even if it requires more lines of code.

## 3. Testing Best Practices
Enforce strict modularity in testing. The repository uses a defined testing pyramid (Unit, Integration, and E2E via Bats). You must adhere to the following testing philosophy:
* **Optimize for Test Speed:** E2E tests are slow and strictly based on existing Critical User Journeys (CUJs). 
* **Push Coverage Down:** If test coverage for a specific edge case or feature can be added at a lower level (Unit or Integration), it is strictly preferred over E2E for speed. 
* **No Redundancy:** Do not replicate a test in the slower E2E path if it is already sufficiently covered in the Integration path.
* **Test Domains:**
  * **Unit Tests:** Focus on isolated, internal functions.
  * **Integration Tests (`tests/integration/`):** Verify module interactions and API compliance in Go and those are time bounded, no more than 10 seconds per execution.
  * **E2E Tests (`tests/e2e/*.bats`):** Use Bats (Bash Automated Testing System) exclusively for high-level, black-box testing of core CUJs.

## 4. Code Quality & Modularity
* Ensure all new code is highly modular, prioritizing small, single-responsibility functions that are easy to unit test.
* Respect the existing repository structure (`cmd/`, `api/`, `internal/`, `tests/`).

## 5. Validation

* Ensure binaries build using `make`
* Ensure linter passes `make lint`
* Ensure test passes `make test`
* Ensure e2e test passes `make e2e-test`
