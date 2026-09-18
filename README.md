# OSS Security Timeline

GitHub 오픈소스 저장소의 업데이트와 CVE·GHSA·OSV 공지를 시간순으로 추적하고, 코드에서 찾은 보안 가설을 제한된 PoC로 검증해 사람이 검토할 비공개 제보 초안까지 연결하는 로컬 보안 조사 도구입니다.

공개 소개 페이지: [ttzero25.github.io/oss-security-timeline](https://ttzero25.github.io/oss-security-timeline/)

프로젝트 제안서: [ttzero25.github.io/oss-security-timeline/proposal.html](https://ttzero25.github.io/oss-security-timeline/proposal.html)

> 코드 후보는 취약점이나 제로데이 확정 결과가 아닙니다. 외부 제보와 CVE/GHSA 요청은 항상 사람이 검토하고 직접 수행합니다.

## 무엇을 제공하나

- GitHub 릴리스·커밋·저장소 보안 공지와 패키지별 GitHub/OSV 공지를 수집합니다.
- CVE와 GHSA 별칭을 하나의 공지로 묶고 게시·수정·최초 관측 시각을 저장합니다.
- 저장소와 패키지별 공지 수, 공개 변경 이력, 향후 공개 공지 추정치를 비교합니다.
- 공지에 연결된 영향 버전과 패치 버전, 참조 커밋의 삭제·추가 코드를 전후로 비교합니다.
- 저장소의 언어·프레임워크·매니페스트·lockfile·엔트리포인트와 조사 범위를 기록합니다.
- Python, JavaScript/TypeScript, Go, C/C++ 및 일부 GitHub Actions 패턴에서 입력부터 위험 동작까지의 코드 가설을 찾습니다.
- 지원되는 후보는 제한된 정상/공격 대조 PoC로 검증하고, 근거 게이트를 통과한 경우에만 GHSA 비공개 제보 초안과 CVE 요청 브리프를 만듭니다.
- 저장소, 패키지, 공지, CVE, CWE, fix 커밋과 코드 후보의 관계를 그래프로 탐색합니다.

## 웹 화면

| 화면 | 용도 |
| --- | --- |
| Home | 누적 저장소·공지·변경·코드 후보·PoC 대조 수와 에이전트 구성 확인 |
| 실험실 | GitHub URL 입력, 수집·심층 조사 실행, 단계별 진행률과 조사 결과 확인 |
| 정리 | 저장소·패키지별 결과, 벤치마크와 공개 공지 추정치 비교 |
| 관계망 | 저장소에서 공지·CVE·CWE·패키지·커밋·코드 후보로 이어지는 관계 탐색 |
| 리포트 | 모든 조사 타겟의 상태와 검증된 PoC 증거, GHSA/CVE 초안 열람 |

실험실에서는 저장소 요약 아래 바로가기로 보안 공지, Fix 전후, 코드 조사, 조사 범위로 이동할 수 있습니다. Fix 전후 화면은 연·월 필터와 공지·파일별 드롭다운을 제공하며, 리포트 화면은 초안이 없는 저장소도 조사 타겟 현황에 표시합니다. 낮/밤 테마 선택은 브라우저에만 저장됩니다.

## 요구 사항

- Python 3.11 이상
- Git
- 공개 GitHub 저장소를 읽을 수 있는 네트워크
- 권장: 읽기 전용 `GITHUB_TOKEN` 또는 로그인된 GitHub CLI
- 선택: 더 강한 PoC 격리가 필요할 때만 Docker
- JavaScript/TypeScript 또는 Go 후보를 실행하려면 해당 로컬 런타임

기본 CLI와 웹에는 추가 Python 패키지가 필요하지 않습니다. 토큰이 없으면 GitHub 비인증 API 한도가 적용됩니다. 인증 값은 DB나 웹 응답에 저장하지 않습니다.

## 빠른 시작

1. 저장소를 복제합니다.

   ```sh
   git clone https://github.com/ttzero25/oss-security-timeline.git
   cd oss-security-timeline
   python3 --version
   ```

2. GitHub API 인증을 준비합니다. 이미 `gh auth login`을 사용했다면 이 단계는 생략할 수 있습니다.

   ```sh
   export GITHUB_TOKEN=YOUR_READ_ONLY_GITHUB_TOKEN
   ```

3. 로컬 웹을 실행합니다.

   ```sh
   python3 tools/web.py --port 8765
   ```

4. 브라우저에서 [http://127.0.0.1:8765/](http://127.0.0.1:8765/)을 열고 실험실에 `https://github.com/owner/repository` 형식의 링크를 입력합니다.

웹은 `127.0.0.1`에만 바인딩하며 한 번에 한 저장소를 조사합니다. 실행 상태는 `data/web-jobs.json`에 저장되고 서버가 중단되면 다음 시작 시 대기열에서 재개됩니다. 진행률은 작업 단계에 따른 예상치이며 파일 단위의 정밀한 완료율은 아닙니다.

## 링크 하나로 심층 조사

웹 실험실과 다음 CLI 명령은 같은 조사 흐름을 사용합니다.

```sh
python3 -m oss_timeline research-run https://github.com/owner/repository --max-candidates 3
```

처리 흐름은 다음과 같습니다.

```text
공개 공지 동기화
  → 저장소 복제·프로파일링
  → 정적 코드 가설 생성
  → 후보 우선순위화·도달성 확인
  → 허용된 PoC 생성
  → 자원 제한 정상/공격 대조
  → 기존 공지·보안 변경 중복 검토
  → 5개 근거 게이트
  → GHSA/CVE 비공개 초안
```

대규모 저장소의 지원 코드 전체를 결정적 샤드로 끝까지 순회하려면 다음처럼 실행합니다. `--max-files`는 샤드 하나의 크기입니다.

```sh
python3 -m oss_timeline research-run https://github.com/owner/repository \
  --complete-scan --max-files 20000 --max-candidates 3
```

기존 감사 결과에서 아직 시도하지 않은 지원 후보의 다음 묶음만 이어서 검증할 수도 있습니다.

```sh
python3 -m oss_timeline research-replay \
  data/research/OWNER_REPOSITORY/COMMIT/audit.json \
  --max-candidates 3
```

웹의 `번들 fixture로 PoC·리포트 self-test`는 외부 저장소 대신 무해한 로컬 취약 fixture를 사용해 PoC 대조와 초안 생성까지 점검합니다. 이 결과는 실제 프로젝트 취약점이 아니며 리포트에서 `fixture/web-self-test`로 구분됩니다.

## CLI 명령

| 명령 | 설명 |
| --- | --- |
| `sync` | 저장소 업데이트·공지·패키지 정보를 한 번 수집 |
| `watch` | 지정한 간격으로 반복 관측 |
| `report` | 수집 결과를 JSON 또는 HTML로 출력 |
| `audit` | 로컬 또는 원격 저장소에서 정적 코드 가설 생성 |
| `research-run` | 수집부터 제한 PoC와 제보 초안까지 실행 |
| `research-replay` | 기존 감사에서 이월된 후보를 이어서 검증 |
| `poc-init` | 수동 검증용 PoC 작업공간과 manifest 생성 |
| `poc-verify` | 정상/공격 대조를 자원 제한 환경에서 실행 |
| `disclosure` | 검증 근거로 GHSA/CVE 초안 생성 |
| `report-status` | 사람의 제보 처리 상태 조회 |
| `report-mark` | 검토·제출·접수 결과를 로컬에 기록 |
| `benchmark` | 버전 관리된 로컬 코퍼스의 정적 탐지 회귀 측정 |
| `benchmark-upstream` | 공개 사례의 고정 커밋 전체 저장소에서 정적 탐지 평가 |

전체 옵션은 다음 명령으로 확인합니다.

```sh
python3 -m oss_timeline --help
python3 -m oss_timeline research-run --help
```

## 수동 PoC와 제보 초안

자동 재현을 지원하지 않는 후보는 억지로 실행하지 않고 중단 사유를 기록합니다. 사람이 직접 검증할 때는 다음 흐름을 사용합니다.

```sh
python3 -m oss_timeline poc-init path/to/audit.json FIND-XXXXXXXXXXXX
python3 -m oss_timeline poc-verify path/to/FIND-XXXXXXXXXXXX/manifest.json
python3 -m oss_timeline disclosure path/to/audit.json FIND-XXXXXXXXXXXX \
  --claim path/to/FIND-XXXXXXXXXXXX/claim.json \
  --evidence path/to/FIND-XXXXXXXXXXXX/evidence.json
```

`claim.json`에는 실제 대상 코드 경로, 공격자 통제, 정상 대조군, 영향과 중복 조사 근거를 작성해야 합니다. `disclosure`가 만드는 `GHSA_CANDIDATE.md`와 `CVE_REQUEST_BRIEF.md`는 로컬 비공개 초안이며 자동 제출되지 않습니다.

사람이 검토하고 제출한 결과만 로컬 상태로 기록합니다.

```sh
python3 -m oss_timeline report-mark path/to/audit.json FIND-XXXXXXXXXXXX --status reviewed
python3 -m oss_timeline report-mark path/to/audit.json FIND-XXXXXXXXXXXX \
  --status submitted --reference '제출 URL 또는 접수 번호'
python3 -m oss_timeline report-status path/to/audit.json FIND-XXXXXXXXXXXX
```

## 자동 재현의 안전 경계

- 기본 실행은 시간·CPU·출력·파일 디스크립터를 제한한 별도 로컬 프로세스입니다.
- macOS에서는 사용 가능한 시스템 sandbox로 네트워크를 차단하고 쓰기를 임시 scratch로 제한합니다.
- Python SSRF는 HTTP 클라이언트를 메모리 스텁으로 바꿔 실제 네트워크에 연결하지 않습니다.
- SQL 후보는 가짜 커서로 조립된 쿼리만 관측하며 실제 DB에 연결하지 않습니다.
- 경로 조작 후보는 임시 scratch 내부의 정상 파일과 `..` 대조만 사용합니다.
- `pickle.loads` 공격 객체의 효과는 고유 문자열의 표준 출력으로 제한합니다.
- JavaScript/TypeScript는 Node 내장 모듈 중심의 제한된 함수만 실행합니다.
- Go는 표준 라이브러리 기반 단일 파일 후보를 해시 확인 후 `GOPROXY=off`로 실행합니다.
- 누락 의존성을 자동 설치하지 않습니다. 허용된 스텁 범위를 벗어나면 실행 전에 중단합니다.
- 더 강한 읽기 전용·네트워크 격리가 필요할 때만 `--container`를 사용합니다.

실제 실행 모드, 생성기, 검증 범위와 정상/공격 대조 결과는 후보별 `evidence.json`에 기록됩니다.

## 검증과 벤치마크

```sh
python3 -m unittest discover -s tests
python3 -m oss_timeline benchmark --min-recall 1 --max-false-positive-cases 0
python3 -m oss_timeline benchmark-upstream --max-files 20000
```

로컬 벤치마크는 탐지 규칙의 회귀를 찾기 위한 합성·집중 사례입니다. 실제 저장소의 전체 탐지율이나 제로데이 발견 성능을 의미하지 않습니다. 자세한 범위는 [benchmarks/README.md](benchmarks/README.md)를 확인하세요.

## 데이터와 수집 범위

| 경로 | 생성 내용 |
| --- | --- |
| `data/timeline.sqlite3` | 저장소, 공지, 패키지, 공개 변경과 연구 상태 |
| `data/checkouts/` | 조사 대상 로컬 복제본 |
| `data/research/` | 프로필, 감사 결과, PoC 증거와 제보 초안 |
| `data/fix-comparisons/` | 공지가 참조한 커밋의 전후 코드 |
| `data/benchmarks/` | 최근 벤치마크 결과 |
| `data/web-jobs.json` | 웹 작업과 재개 상태 |

웹 수집은 기본적으로 API 페이지와 매니페스트를 각각 최대 100개, 공지 참조 커밋을 최대 5개까지 처리합니다. 두 번째 관측부터는 마지막 동기화 이후 커밋만 요청해 API 사용량을 줄입니다. 첫 수집의 과거 이력이 잘렸다면 완료로 표시하지 않고 경고를 유지합니다.

여기서 “전수”는 접근 가능한 공개 API와 설정한 상한 안에서의 전수를 뜻합니다. 기본 브랜치 밖의 기록, 삭제된 과거 패키지, 모든 CVE 등록부 항목은 빠질 수 있습니다. 코드 전체 순회는 `--complete-scan`을 명시한 경우에만 수행합니다. 후보 0건은 안전 판정이 아닙니다.

공개 공지 예측은 과거 게시 건수로 향후 12개월을 추정합니다. 공개 공지 5건과 관측 기간 24개월이 확보되지 않으면 계산하지 않으며, 관측할 수 없는 미공개 제로데이 발생 수는 예측하지 않습니다.

## 프로젝트 구조

| 위치 | 내용 |
| --- | --- |
| [agents/](agents/README.md) | 12개 에이전트 역할과 입력·출력 |
| [rules/](rules/README.md) | 탐지·오케스트레이션·검증·제보 기준 |
| [tools/](tools/README.md) | CLI와 로컬 웹의 상세 동작 |
| [benchmarks/](benchmarks/README.md) | 정적 탐지 회귀 코퍼스와 평가 방법 |
| [troubleshooting/](troubleshooting/README.md) | API 제한, 조사 누락, PoC 오류 해결 |
| `oss_timeline/` | CLI, 수집기, 저장소, 스캐너와 오케스트레이터 |
| `tests/` | 수집·탐지·PoC·제보 게이트 회귀 검사 |

타임라인 흐름:

```text
InventoryAgent → (ChangeAgent + AdvisoryAgent) → CandidateAgent → DB·보고서
```

코드 조사 흐름:

```text
RepositoryProfilerAgent → SourceScanAgent → ReachabilityGateAgent
→ ResearchOrchestrator → PocValidatorAgent → DuplicateReviewAgent
→ EvidenceGateAgent → DisclosureAgent → 연구 타임라인
```

역할별 설명은 [agents/README.md](agents/README.md), 실행 규칙은 [rules/README.md](rules/README.md)를 참고하세요.

## 결과 해석과 책임 있는 공개

- 정적 분석 결과는 검토 후보입니다.
- PoC 대조 성공은 모델링한 경로의 기계적 재현 근거이지 모든 배포 환경의 영향 증명이 아닙니다.
- 공개 공지 중복 검토가 없거나 스냅샷이 오래되면 초안 생성을 중단합니다.
- 공지 참조 커밋의 diff는 조사 근거이며 해당 변경이 완전한 fix라는 자동 판정이 아닙니다.
- 비공개 제보 전 대상 커밋, 도달성, 기본 설정, 영향, 중복 여부를 사람이 다시 확인해야 합니다.

제보는 프로젝트의 `SECURITY.md` 또는 [GitHub 비공개 취약점 제보 절차](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)를 따르세요. CVE 식별자는 프로젝트 관리자나 CNA의 절차에 따라 요청합니다.

주요 공개 데이터 원천은 [GitHub Repository Security Advisories API](https://docs.github.com/en/rest/security-advisories/repository-advisories), [GitHub Global Security Advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories), [GitHub Git Trees API](https://docs.github.com/en/rest/git/trees), [OSV](https://osv.dev/)입니다.

문제가 생기면 [문제 해결 가이드](troubleshooting/README.md)를 먼저 확인하세요.
