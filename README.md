# Project Apollo
- Project Apollo는 한글 워드 프로세서(HWP)를 악용한 표적 문서 공격(예: [아르테미스 작전](https://www.genians.co.kr/blog/threat_intelligence/dll?fbclid=IwZnRzaAO4AfFleHRuA2FlbQIxMQBzcnRjBmFwcF9pZAo2NjI4NTY4Mzc5AAEeToGm8Va8h0hKoVNYMSWVHw4wK_oYIk1URJWz58fIyS8gArguWyGMS0rWkBo_aem_kye8VIu1fLYt2wq4e7ba2g) 등)을 연구하고 조기 탐지 규칙을 실험하기 위한 간단한 검사 도구입니다.
- 본 프로젝트는 자동 차단 솔루션이 아니라, HWP 기반 악성 행위의 흔적을 찾아내는 정적·휴리스틱 검사를 제공하여 한글 워드 프로세스를 사용하는 환경에서 잠재적 위협을 조기에 식별하는 데 목적이 있습니다.

**목표**
- HWP 문서에서 악성 행위(임베디드 스크립트, 의심 메타데이터, 비정상 구조 등)를 식별하는 기초 검사 제공
- 플러그인 형태로 규칙·파서·출력 형식을 쉽게 추가·교체 가능하게 구현
- 안전한 분석 워크플로우(격리 환경을 전제로 한 샘플 처리) 권장

**주요 기능**
- HWP 포맷 기반의 정적 구조 분석
- 휴리스틱 및 시그니처 기반 의심 패턴 감지
- 검사 결과를 구조화(텍스트/JSON)하여 자동화 파이프라인에 연결 가능
- 모듈화된 코드 구조로 룰 추가·파서 개선·리포트 확장 용이

## 탐지 대상 (현재 방어/검출 가능한 공격 예시)
아래 항목들은 현재 코드베이스에서 정적·휴리스틱 방식으로 탐지하거나 경고를 발생시키는 대표적인 위협 벡터입니다.

- **임베디드 실행 파일(PE/DLL) 은닉**: 스트림 내 `MZ`(PE) 헤더를 탐지하여 실행 파일(DLL/EXE) 은닉을 경고합니다 (`internal/detect`).
- **압축된 페이로드 내부의 PE**: zlib 등으로 압축된 스트림을 해제하여 내부에 PE가 있는지 검사합니다(압축 해제 시 최대 크기 제한 적용).
- **고엔트로피 데이터(쉘코드/바이너리 페이로드 의심)**: 스트림 엔트로피 계산으로 쉘코드나 암호화된 바이너리 컨텐츠를 의심합니다.
- **이미지 위장 악성코드**: 확장자가 이미지지만 파일 시그니처가 일치하지 않거나 내부에 스크립트(JScript/PowerShell) 패턴이 포함된 경우 탐지합니다.
- **스크립트 기반 페이로드**: `JScript`, `Javascript`, `powershell` 등의 키워드가 포함된 스트림을 탐지합니다.
- **EPS / PostScript 벡터**: EPS 포맷 특성(예: `%!` 프리픽스)으로 취약점 벡터 가능성을 경고합니다.
- **악성 링크 / 커맨드 패턴**: `javascript:`, `vbscript:`, `file://`, `powershell:` 등 의심스러운 URI/커맨드 패턴을 검색합니다.
- **HWPX 내부 바이너리(BinData 등) 검사**: HWPX(zip) 내부의 `BinData` 및 실행파일 관련 항목을 검사합니다(Zip Bomb 대비 제한 적용).

제한 사항 및 주의점:

- 본 도구는 **정적·휴리스틱 검사용**이며 런타임 행위를 차단하거나 완전한 악성코드 판정을 내리지는 않습니다. 오탐(특히 고엔트로피/비표준 바이너리)에 유의하십시오.
- 압축 해제 및 대용량 스트림 처리에는 `internal/detect.MaxDecompressSize` 상한을 적용하여 Zip Bomb을 완화합니다(완전 차단 아님).
- 더 정밀한 판정이 필요하면 샌드박스·동적 분석(실행 기반) 또는 시그니처 기반 엔진(AV)과 연계하십시오.
- 탐지 룰을 추가하거나 민감도를 조정하려면 `internal/detect`의 함수들을 수정하고 테스트를 보강하세요.

---

### 기술적 상세 (항목별)

- **임베디드 실행 파일(PE/DLL) 은닉**
	- 코드 위치: `internal/detect/detect.go`의 `isPEHeader()` 및 `CheckStreamContent()`.
	- 동작: 바이트 스트림의 시작 2바이트가 `0x4D 0x5A`(`"MZ"`)인지 검사하여 즉시 `CRITICAL` 경고를 생성합니다.
	- 한계: 일부 PE 페이로드는 앞부분이 패딩/암호화되어 `MZ`가 숨겨질 수 있음. 또한 PE 식별만으로 로직 실행 의도를 확정할 수 없습니다.
	- 개선 제안: `debug/pe` 패키지 또는 `github.com/saferwall/pe` 같은 라이브러리로 PE 내부(섹션, 임포트 테이블, 서명, 타임스탬프) 파싱을 추가하여 추가 지표(예: 비어있는 임포트 테이블, 의심스러운 섹션명 등)를 수집하세요.

- **압축된 페이로드 내부의 PE**
	- 코드 위치: `tryDecompress()` 및 `CheckStreamContent()`에서 압축 해제 후 `isPEHeader()` 검사.
	- 동작: zlib로 해제 시도 후 최대 `MaxDecompressSize`(현재 10MiB)만큼 읽어 검사합니다.
	- 한계: zlib 외 다른 압축·인코딩(xz, lzma, base64 혼합 등)은 감지되지 않음.
	- 개선 제안: 추가 압축 포맷(예: gzip, lz4) 및 common encodings(base64, uuencode) 디코딩 로직을 계층적으로 적용하세요. 압축체인(중첩 압축) 탐지도 고려하세요.

- **고엔트로피 데이터(쉘코드/바이너리 페이로드 의심)**
	- 코드 위치: `calculateEntropy()`와 `CheckStreamContent()`의 임계값 비교(현재 `>7.8` 또는 `>7.0`과 `.dll` 포함시 경고).
	- 동작: Shannon 엔트로피 계산으로 랜덤성(암호화/압축/바이너리)을 판단합니다.
	- 한계: 정상 압축 데이터나 리소스(이미지, 서체 등)도 높은 엔트로피를 보일 수 있어 오탐 소지.
	- 개선 제안: 엔트로피 경고 시 확장자·스트림 컨텍스트(예: `section`, `prvimage` 등 안전 목록) 및 파일 시그니처를 교차검증하거나, PE 파싱 결과를 결합하여 신뢰도를 계산하세요.

- **이미지 위장 악성코드**
	- 코드 위치: `hasImageSignature()` 및 `CheckStreamContent()`의 이미지 검증 블록.
	- 동작: JPEG/PNG/GIF/BMP/WMF 시그니처를 검사하고, 시그니처가 없으면서 `JScript` 등 스크립트 문자열을 포함하면 `CRITICAL`로 판단합니다.
	- 한계: 일부 포맷 변종이나 손상된 이미지가 오탐을 유발할 수 있습니다.
	- 개선 제안: 파일 포맷별 심층 헤더 파서(예: PNG chunk 검사) 도입 및 이미지 메타데이터(EXIF) 내 의심 문자열 검색을 추가하세요.

- **스크립트 기반 페이로드**
	- 코드 위치: `CheckStreamContent()` 내 `bytes.Contains(...)` 검색 및 `suspiciousLinkRegex`.
	- 동작: 스트림 내에 `JScript`, `Javascript`, `powershell` 같은 키워드 등장 시 `CRITICAL` 경고.
	- 한계: 단순 키워드 매칭 방식이며 인코딩·난독화된 스크립트는 우회 가능.
	- 개선 제안: 문자열 디코딩(유니코드, UTF-16LE/BE), 흔한 난독화 패턴(문자 연결, URL 인코딩) 해제 로직을 추가하세요. 정규표현식 기반 시그니처나 YARA 룰을 도입하면 정확도를 높일 수 있습니다.

- **EPS / PostScript 벡터**
	- 코드 위치: `CheckStreamContent()`의 EPS 검사(`bytes.HasPrefix(data, []byte("%!"))`).
	- 동작: PostScript 특성(문서 시작 `"%!"`)을 확인하여 `CRITICAL` 보고.
	- 한계: 단순 접두사 검사만 수행하므로 PostScript 내부 인젝션 벡터의 유해성 평가는 제한적입니다.
	- 개선 제안: PostScript 명령어 집합에서 `run`/`exec`/`file`과 같이 외부 실행/파일 쓰기 관련 토큰을 검사하도록 확장하세요.

- **악성 링크 / 커맨드 패턴**
	- 코드 위치: `suspiciousLinkRegex` (`internal/detect/detect.go`)와 관련 검사.
	- 동작: 스트림에서 `javascript:`, `file://`, `powershell:` 등 패턴을 정규식으로 검색합니다.
	- 한계: 정규식 기반이며 난독화(예: 공백·주석 삽입, 문자열 연결)로 우회될 수 있습니다.
	- 개선 제안: HTML/URI 파서로 링크 구조를 파싱하고, 존재하는 경우 도메인/경로 검증 및 URL 디코딩을 수행하세요.

- **HWPX 내부 바이너리(BinData 등) 검사**
	- 코드 위치: `internal/scan/ScanHWPX()`에서 `BinData` 및 `.exe/.dll/.eps` 필터링과 `io.LimitReader` 적용.
	- 동작: ZIP 내부 항목을 제한적으로 열어 `CheckStreamContent()`에 전달합니다. 대용량은 `detect.MaxDecompressSize`로 제한합니다.
	- 한계: 현재 필터링은 검사 대상 축소에 유리하지만, 악성 파일이 다른 경로에 숨겨진 경우 누락될 수 있습니다.
	- 개선 제안: `BinData` 외에도 문서 내부 참조(예: XML 내 외부 리소스 참조)를 스캔하고, ZIP 내 전체 파일명을 색인하여 잠재적 숨김 경로를 탐색하세요.

---

### DLL 사이드로딩(분석 및 권고)

현재 코드베이스가 **DLL 사이드로딩을 런타임 동작(실행 시 로드 경로 조작)까지 방지하거나 완전히 탐지**하는 것은 아닙니다. 다만 다음과 같은 정적 탐지 지표를 제공하여 사이드로딩 시도를 간접적으로 포착할 수 있습니다:

- **임베디드 DLL 탐지**: HWPX 내부의 `.dll` 스트림이나 OLE 바이너리 스트림에서 `MZ` 헤더를 찾아 `CRITICAL`/`WARNING`을 발생시킵니다. 이는 문서에 DLL이 포함되어 배포되는 경우를 탐지합니다.
- **고엔트로피/비정상적 DLL 경로명**: 엔트로피 및 스트림 이름 기반 검사로 의심스러운 바이너리를 분류합니다.

하지만 진정한 '사이드로딩'은 악성 DLL이 정상 실행파일과 동일한 디렉터리에 배치되어 정상 프로세스가 로드하도록 유도하는 런타임 기법입니다. 정적 문서 검사만으로는 다음을 포착하기 어렵습니다:

- 문서가 파일 시스템에 DLL을 쓰고 실행파일을 호출하는 런타임 행위
- 시스템 수준의 DLL 검색 순서 악용(예: 현재 디렉터리 우선 로딩) 또는 안전하지 않은 LoadLibrary 호출
- 정상 EXE와 동일한 이름을 가진 DLL(이름 유사성) 배치 여부

권고 구현(단계적 개선)

1. OLE/ActiveX/외부 링크 분석 강화: HWP(OLE) 파싱 시 CLSID/ProgID, 외부 스크립트가 `CreateObject`, `ShellExecute`, `LoadLibrary` 같은 API 호출을 암시하는지 검색하여 잠재적 파일 생성·실행 흐름을 탐지하세요.
2. PE 심층분석 추가: `debug/pe`를 사용하여 DLL의 Export 리스트·임포트 테이블·섹션 특성(예: 비정상적 섹션명, 실행 권한 섹션) 등을 추출, 정상 시스템 DLL과의 차이를 기반으로 사이드로딩 의심도를 산출하세요.
3. 파일명·경로 히유리스틱: `kernel32.dll` 등 시스템 DLL과 유사한 이름을 가진 DLL(예: `kernel32-compat.dll`, `notepad.exe`와 같은 이름의 `.dll`)을 문서에서 추출된 파일명과 대조해 의심 표식으로 표시하세요.
4. 서명/인증서 검증: 포함된 PE가 코드 서명되어 있는지 확인하고, 신뢰할 수 없는 서명 또는 무서명(또는 서명 위조 의심)을 경고하세요.
5. 동적 분석 연계 권장: 문서가 실제로 파일을 드롭하거나 프로세스를 실행하는지 확인하려면 샌드박스 기반 모니터링(파일 생성, 프로세스 생성, DLL 로드 이벤트 추적)을 도구 체인에 추가하세요.

구체적 코드 작업 예시:

- `internal/detect`: 새로운 함수 `analyzePE(pathOrStream []byte)`를 추가해 `debug/pe`로 임포트/익스포트/섹션을 파싱한 뒤 사이드로딩 지표를 반환.
- `internal/scan`: HWP(OLE) 스트림을 읽을 때 스트림명/컨텐츠에 `LoadLibrary`/`CreateProcess` 등 문자열이 포함되어 있는지 별도로 검사.
- `internal/report`: 탐지 결과에 `sideload_score` 같은 정량적 필드를 추가하여 최종 판정에 반영.

요약: 현재 도구는 포함된 DLL/PE를 잘 찾아내며 이는 사이드로딩 시도의 중요한 신호입니다. 그러나 '사이드로딩 공격이 실제로 성공하는지'를 확인하려면 PE 심층분석과 동적 행위 모니터링을 결합하는 추가 작업이 필요합니다.

## 빠른 시작

**빌드**
```bash
# 일반 GUI 바이너리 빌드 (예: macOS/Linux)
go build -o bin/project_apollo ./cmd/project_apollo

# Windows용 빌드(예시)
make windows

# CLI 전용 바이너리 빌드(헤드리스 분석)
# 빌드 태그 'cli'를 사용하여 GUI 대신 CLI 진입점을 빌드합니다.
go build -tags cli -o bin/project_apollo_cli ./cmd/project_apollo
```

참고: 저장소의 `Makefile`은 Windows 크로스빌드 시 기본적으로 `bin/HWPScanner.exe` (GUI) 및
`bin/HWPScanner_CLI.exe` (CLI) 등 다른 출력 파일명을 사용합니다. `go build` 예시는 호스트 빌드
출력을 보여주며, `make` 명령을 사용할 경우 실제 생성되는 파일명이 다를 수 있으니 유의하세요.

**프로젝트 구조**
- `cmd/project_apollo` — CLI 진입점
- `internal/detect` — 탐지 규칙과 룰 관리
- `internal/scan` — 포맷별 스캐너(`hwp.go` 포함)
- `internal/report` — 결과 형식화 및 출력 플러그인
- `internal/ui` — 콘솔 출력/테마 유틸리티
# Project Apollo

Project Apollo는 한글 워드 프로세서(HWP/HWPX)를 악용한 표적 문서 공격을 연구하고 조기 탐지 규칙을 실험하기 위한 연구·분석 보조 도구입니다. 이 프로젝트는 자동 차단 솔루션이 아니며, 분석가와 엔지니어가 규칙을 빠르게 검증·확장할 수 있도록 설계되었습니다.

**핵심 요약**
- 목적: HWP/HWPX 문서에서 임베디드 코드, 의심 메타데이터, 비정상 스트림 구조 등 잠재적 위협을 식별하기 위한 기초 정적·휴리스틱 검사를 제공
- 범위: 연구·샘플 분석 및 규칙 개발 보조 (운영용 검증 필요)

**목표**
- HWP/HWPX 내부 스트림 검사로 의심스러운 바이너리·스크립트·링크를 식별
- 룰·파서·리포트를 플러그인처럼 확장 가능하게 구현
- 샘플 처리는 항상 격리된 환경(샌드박스)에서 수행 권장

## 주요 기능
- HWP(OLE) 및 HWPX(ZIP) 포맷 스트림 정적 분석
- 휴리스틱·시그니처 기반 패턴 탐지(스크립트, PE 헤더, 고엔트로피 등)
- 분석 결과를 텍스트/JSON 등으로 출력할 수 있도록 모듈화된 리포트
- GUI(데모)와 CLI(헤드리스) 두 가지 진입점 제공

## 요구사항
- Go >= 1.26 (모듈의 `go.mod` 기준)
- (옵션) GUI 모드: `fyne` 기반 UI 관련 라이브러리가 필요합니다
- (Windows 크로스빌드 필요 시) `zig` 설치 및 환경설정 필요 (Makefile에서 Zig를 사용하여 Windows용 바이너리를 크로스컴파일합니다)

참고: 현재 저장소의 `go.mod` 파일에는 로컬 모듈명으로 `project_apollo`가 설정되어 있습니다. 공개 저장소에 업로드하거나 모듈을 외부에서 `go get`/`go install`로 사용할 계획이라면 `go.mod`의 `module` 이름을
`github.com/Jin-Doh/Project-Apollo` 같은 정식 모듈 경로로 변경하는 것을 권장합니다. 로컬 빌드는 현재 제공된 `go build`/`make` 명령으로 정상 동작합니다.

> 보안 주의: 악성 샘플을 다룰 때는 반드시 오프라인/샌드박스 환경에서 실행하세요. 공개 저장소에 민감 샘플을 업로드하지 마십시오.

## 빠른 시작

빌드 및 실행(요약)

GUI(기본) 빌드 및 실행:
```bash
# GUI 바이너리(플랫폼별) 빌드
go build -o bin/project_apollo ./cmd/project_apollo

# 실행 (GUI 창이 뜹니다)
./bin/project_apollo
```

CLI(헤드리스) 빌드 및 실행:
```bash
# 로컬(호스트)용 CLI 빌드
go build -tags cli -o bin/project_apollo_cli ./cmd/project_apollo

# 또는 Makefile 사용
make cli-local   # 호스트용 CLI 빌드
make cli         # Zig를 이용한 Windows 크로스빌드 (환경 필요)

# 실행
./bin/project_apollo_cli /path/to/sample.hwp
./bin/project_apollo_cli /path/to/samples/
```

Makefile 주요 타겟
- `make windows` : GUI Windows 크로스빌드 (Zig 필요)
- `make cli` : CLI Windows 크로스빌드 (Zig 필요)
- `make cli-local` : 호스트에서 CLI 빌드

생성 파일 예시:
- `make windows` -> `bin/HWPScanner.exe` (GUI, Windows)
- `make cli` -> `bin/HWPScanner_CLI.exe` (CLI, Windows)
- `make cli-local` -> `bin/project_apollo_cli` (호스트용 CLI)

## 코드베이스 구조(요약)
- `cmd/project_apollo` — 진입점: GUI `main.go` (빌드태그 `!cli`) 및 CLI `cli.go` (빌드태그 `cli`)
- `internal/detect` — 탐지 규칙 및 휴리스틱 구현
- `internal/scan` — HWP/HWPX 스트림 스캐너
- `internal/report` — 분석 결과 생성 및 형식화
- `internal/ui` — GUI 테마/출력 유틸리티
- `bin/` — 빌드 산출물

## 테스트
- 단위 테스트 실행:
```bash
go test ./...
```
- 현재 테스트가 추가된 패키지(샘플): `internal/detect`, `internal/scan`, `internal/report`, `internal/ui`

## 설계 및 확장 포인트
- 탐지 룰 추가: `internal/detect`에 룰을 추가하고 관련 테스트 샘플을 포함하세요. 각 룰은 `설명`, `심각도`, `권장 조치` 메타데이터를 가질 것을 권장합니다.
- 포맷 파서 개선: HWP 내부 구조를 더 깊게 분석하려면 `internal/scan`의 파서를 확장하세요.
- 리포트 포맷: `internal/report`에 새로운 출력기(JSON, CSV 등)를 추가하여 SIEM이나 자동화 파이프라인과 연동할 수 있습니다.

## 빌드/배포 유의사항
- Windows 크로스빌드는 Zig(C compiler)와 `CGO_ENABLED=1`를 사용합니다. Zig가 설치되어 있지 않으면 `make windows`/`make cli`가 실패합니다.
- GUI 빌드는 플랫폼별 GUI deps(X11, Cocoa 등)가 필요할 수 있습니다. GUI 빌드에서 문제가 발생하면 `-tags cli`로 CLI 전용 빌드를 시도하세요.

## 기여
- PR 환영: 새로운 룰, 파서 개선, 리포트 포맷, 문서 개선 등을 PR로 제출해 주세요.
- PR 템플릿: 변경 목적, 테스트 방법, 샘플(또는 샘플 메타데이터)을 명시해 주세요.

## 라이선스
- 이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 확인하세요.
