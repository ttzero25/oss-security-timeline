# 오픈소스 보안 타임라인

## 프로젝트 목적

GitHub 오픈소스 저장소의 변경과 공개 취약점 공지를 한 시간축에 모아, 어떤 저장소와 패키지에 보안 이슈가 집중됐는지 확인합니다. 코드 조사에서는 미공개 취약점의 **가설**을 만들고, 실제 코드와 PoC로 검증된 결과만 비공개 GHSA 제보 초안과 CVE 요청 브리프로 정리합니다.

## 한눈에 보기

- GitHub 릴리스·커밋, 저장소 보안 공지, 패키지별 검토/미검토 GHSA 및 OSV 기록을 수집합니다.
- CVE/GHSA 별칭을 같은 공지로 묶고, 게시·수정·최초 관측 시각을 저장해 타임라인과 저장소·패키지 순위를 만듭니다.
- 실험실의 보안 공지 표에는 GHSA/원본 식별자와 등록된 CVE를 별도 칸에 표시하고, 공지 원문에 명시된 CWE 유형만 보여줍니다.
- 실험실은 공지의 영향 버전과 패치 버전을 비교하고, 공지가 같은 저장소의 커밋을 직접 참조하면 삭제·추가된 코드 줄을 나란히 보여줍니다. 이 참조만으로 해당 커밋이 완전한 fix라고 판정하지 않습니다.
- 공개 변경 메시지와 Python·JavaScript/TypeScript·Go·C/C++ 코드에서 검토 후보를 찾습니다. Python은 단순 할당과 모듈 간 함수·해석 가능한 클래스 인스턴스 메서드 호출을 최대 네 단계까지 추적하고, 변경되지 않는 리터럴 allowlist 조회는 고정값 경계로 취급합니다. JavaScript/TypeScript는 일반 이름 함수와 화살표 함수의 스코프를 분리하고 상대경로 ESM/CommonJS 호출을 제한적으로 추적합니다. Go는 HTTP·CLI 입력이 같은 패키지나 로컬 패키지 함수를 거쳐 셸 실행 또는 외부 HTTP 요청으로 이어지는 경로를 제한적으로 추적합니다. 각 분석은 입력→호출→위험 동작의 코드 경로를 남깁니다. C/C++는 외부 입력이 셸 실행, 비상수 포맷 문자열, 위험 문자열 복사로 이어지는 보수적 패턴만 다룹니다. 후보는 취약점이나 제로데이 확정 결과가 아닙니다.
- 심층 조사 전에 커밋별 저장소 프로필을 만들어 언어 분포, 프레임워크, 프로젝트 유형, 패키지·빌드 매니페스트, lockfile, HTTP·CLI·메시지 엔트리포인트, 최근 변경 파일과 미지원 코드 파일 수를 기록합니다. 이 범위 원장은 “후보 0건”을 전수 안전 판정으로 오인하지 않게 합니다.
- Research Orchestrator는 최근 변경 경로를 후보 우선순위에 반영하고, 기본 설정 도달성 확인, 제한된 Python·JavaScript·Go 후보의 실제 함수 호출 PoC, 격리 대조, 수집된 공개 공지 중복 점검을 연결합니다. JavaScript 자동 실행은 Node 내장 모듈만 가져오고 import 외 최상위 실행문이 없는 단일 default export 함수로 제한합니다. Go는 표준 라이브러리만 쓰는 단일 파일·단일 함수 HTTP 핸들러를 원문 해시 확인 후 임시 디렉터리에서 `GOPROXY=off`로 실행합니다. 마지막으로 외부 도달성·기본 설정·공격자 통제·보안 영향·기존 공지 중복의 다섯 근거를 기록합니다. 게이트를 통과한 결과만 제보 **초안**으로 만들며 외부 제출과 CVE/GHSA 번호 부여는 자동으로 하지 않습니다.
- 로컬 웹의 Home에서 누적 탐지와 에이전트 역할을, 실험실에서 저장소별 조사 상태를, 정리에서 OSS별 요약을 확인할 수 있습니다. 관계망은 데이터 연결을, 리포트는 CLI에서 생성된 검증 결과와 비공개 초안을 읽기 전용으로 보여줍니다.
- 웹 시작 시 과거 `audit.json`과 `orchestration.json` 쌍을 실행하지 않고 타임라인 DB에 이관합니다. 정리 화면은 `미실행`, `정적 조사만 완료`, `완료 · 후보 없음`, `완료 · 검토 후보 있음`, `완료 · 초안 준비`를 구분합니다.

Python 3.11 이상이 필요합니다. 기본 CLI와 웹 화면에는 추가 Python 패키지나 Docker가 필요하지 않습니다. 웹은 `GITHUB_TOKEN`이 없으면 설치·로그인된 GitHub CLI의 인증을 메모리에서만 활용합니다. 어느 쪽도 없으면 비인증 API 한도가 적용되므로 읽기용 토큰을 권장합니다. 더 강한 PoC 격리가 필요할 때만 Docker와 `--container`를 사용합니다.

## 신규 팀원을 위한 빠른 시작

1. 비공개 저장소 접근 권한을 받은 뒤 프로젝트를 복제합니다.

   ```sh
   git clone https://github.com/ttzero25/oss-security-timeline.git
   cd oss-security-timeline
   python3 --version
   ```

2. 읽기용 GitHub 토큰을 환경 변수로 제공합니다. 이미 `gh auth login`으로 로그인했다면 웹 실행 시 GitHub CLI 인증을 자동 사용하므로 이 단계는 생략할 수 있습니다. 조사할 공개 저장소 URL은 실험실 화면에서 입력합니다.

   ```sh
   export GITHUB_TOKEN=YOUR_READ_ONLY_GITHUB_TOKEN
   ```

3. 웹 화면을 실행하고 브라우저에서 [http://127.0.0.1:8765/](http://127.0.0.1:8765/)을 엽니다. 실험실에서 `https://github.com/owner/repo` 형식의 링크를 입력하면 공개 공지 수집, 저장소 프로파일링, 정적 코드 조사와 지원되는 제한 PoC 대조를 백그라운드에서 시작합니다. 연구 단계 변화는 공개 공지와 구분된 이벤트로 같은 타임라인 DB에 저장됩니다. Home은 누적 수치, 정리는 OSS별 결과, 관계망은 데이터 간 연결입니다. 서버는 `127.0.0.1`에만 바인딩합니다.

   ```sh
   python3 tools/web.py --port 8765
   ```

4. 다른 터미널에서 회귀 검사를 실행합니다.

   ```sh
   python3 -m unittest discover -s tests
   ```

5. 라벨된 로컬 코퍼스로 현재 정적 탐지 기준선을 측정합니다. 결과는 `data/benchmarks/latest.json`에 저장되고 웹의 정리 화면에도 표시됩니다.

   ```sh
   python3 -m oss_timeline benchmark
   ```

웹은 한 번에 한 저장소를 조사하며 API 페이지와 매니페스트를 각각 최대 100개, 공지 참조 커밋은 최대 5개까지 읽습니다. 두 번째 수집부터는 마지막 관측 시각 이후 커밋만 요청해 API 사용량을 줄이되, 첫 수집에서 잘린 과거 이력은 완료로 오인하지 않고 경고를 유지합니다. 조사 완료 뒤 실험실의 수집 범위와 경고를 확인하세요. CWE와 참조 커밋 비교는 새 수집부터 채워지므로 기존 저장소는 다시 수집해야 합니다. 더 세밀한 범위 설정과 정기 관측에는 CLI의 `sync`·`watch`를 사용합니다. 문제가 생기면 [troubleshooting](troubleshooting/README.md)을 먼저 확인하세요.

## 코드 조사와 제보 흐름

`python3 -m oss_timeline audit https://github.com/owner/repo`는 공개 저장소의 최신 커밋을 새 로컬 디렉터리에 복제해 코드 가설을 `data/research/`에 기록합니다. 로컬 체크아웃은 `python3 -m oss_timeline audit /path/to/checkout --repo owner/repo`로 조사할 수 있습니다. 출력된 `audit.json`에서 후보 ID와 조사 범위를 확인합니다.

지원되는 제한 자동화는 아래 명령으로 실행합니다. URL을 입력하면 먼저 공개 공지를 갱신해 중복 검토 스냅샷을 만든 뒤 코드를 조사합니다. 기본 PoC는 별도 임시 작업공간, 제한된 환경 변수, 실행 시간·출력 제한을 둔 로컬 subprocess에서 실행하며 Linux에서는 추가 OS 자원 한도를 적용합니다. 이 방식은 컨테이너 수준의 파일·네트워크 격리는 아니므로 더 강한 격리가 필요하면 `--container`를 추가합니다. 안전한 자동 재현 템플릿이 없는 후보는 억지로 실행하지 않고 `orchestration.json`에 중단 사유를 남깁니다.

```sh
python3 -m oss_timeline research-run https://github.com/owner/repo --max-candidates 3
```

후보가 남으면 `poc-init`으로 `proof.py`, `manifest.json`, `claim.example.json`을 준비합니다. 조사한 커밋의 **실제 앱 경로**를 호출하도록 PoC를 완성하고, 정상 입력 대조군과 보안 영향을 명시한 `claim.json`을 작성하세요. `poc-verify`는 기본적으로 자원 제한 로컬 subprocess에서 두 입력을 실행합니다. 네트워크 차단과 읽기 전용 저장소 마운트가 필요하면 `--container`를 사용합니다. 재현 결과와 코드 인용이 같은 커밋에 맞고, 기존 공지 조사 근거가 채워지면 `disclosure`가 `GHSA_CANDIDATE.md`와 `CVE_REQUEST_BRIEF.md`를 만듭니다.

```sh
python3 -m oss_timeline poc-init path/to/audit.json FIND-XXXXXXXXXXXX
python3 -m oss_timeline poc-verify path/to/FIND-XXXXXXXXXXXX/manifest.json
python3 -m oss_timeline disclosure path/to/audit.json FIND-XXXXXXXXXXXX \
  --claim path/to/FIND-XXXXXXXXXXXX/claim.json \
  --evidence path/to/FIND-XXXXXXXXXXXX/evidence.json
```

두 파일은 로컬의 비공개 제출용 초안이며 웹의 `리포트` 탭에도 자동으로 나타납니다. 웹은 파일을 읽기만 하고 실행·수정·제출하지 않습니다. 보고 전 코드 경로와 PoC가 같은 문제를 입증하는지 사람이 검토하고, [GitHub 비공개 취약점 제보](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately) 또는 프로젝트 보안 정책을 따라 직접 제출하세요. CVE 번호는 [관리자 또는 해당 CNA 절차](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories)에 따라 요청합니다.

## 프로젝트 구조

| 위치 | 내용 |
| --- | --- |
| [agents](agents/README.md) | 11개 역할별 입력·출력과 실행 흐름 |
| [tools](tools/README.md) | CLI 안내와 로컬 수집·조회 웹 도구 |
| [rules](rules/README.md) | 코드 탐지, PoC 검증, 비공개 제보 기준 |
| [troubleshooting](troubleshooting/README.md) | API 제한·PoC 실행·수집 누락 등의 해결 방법 |
| `oss_timeline/` | 실행 코드와 SQLite 저장·보고서 생성 |
| `tests/` | 수집·중복 제거·PoC·제보 게이트 회귀 검사 |
| `benchmarks/` | 취약·정상 대조 사례와 정적 탐지 성능 기준선 |
| `data/` | 실행 중 생성되는 DB, 복제본, PoC, 비공개 초안; Git 제외 |

공개 데이터 흐름은 `InventoryAgent → (ChangeAgent + AdvisoryAgent 병렬) → CandidateAgent`입니다. 코드 조사 흐름은 `RepositoryProfilerAgent → SourceScanAgent → ReachabilityGateAgent → ResearchOrchestrator → PocValidatorAgent → EvidenceGateAgent → DisclosureAgent`이며 결과 상태가 다시 타임라인에 들어갑니다. 이 역할들은 재현 가능한 Python 모듈이며, 지원 범위를 벗어난 후보는 사람의 분석 대상으로 남깁니다.

## 결과를 해석할 때

“전수”는 접근 가능한 공개 API 페이지와 설정한 수집 상한 안에서의 전수를 뜻합니다. 기본 브랜치 밖의 커밋, 삭제된 과거 패키지, CVE 전체 등록부의 모든 항목은 포함되지 않을 수 있습니다. API 실패·페이지 제한·Git 트리 잘림은 결과의 `coverage`와 `warnings`에 표시됩니다. 공지 수정 이력은 정기 관측을 시작한 시점부터 기록합니다.

수치 예측은 과거 **공개 보안 공지 게시 건수**로 향후 12개월을 추정합니다. 공개 공지 5건과 관측 기간 24개월 미만이면 산출하지 않으며, 관측할 수 없는 미공개 제로데이 발생 수는 예측하지 않습니다. 코드 스캔의 빈 결과도 안전성의 증거가 아닙니다.

데이터 원천: [GitHub 저장소 보안 공지 API](https://docs.github.com/en/rest/security-advisories/repository-advisories), [GitHub 글로벌 보안 공지 API](https://docs.github.com/en/rest/security-advisories/global-advisories), [GitHub Git Trees API](https://docs.github.com/en/rest/git/trees), [OSV](https://osv.dev/).

내장 벤치마크는 합성 사례의 회귀 감지용이며 실제 저장소의 탐지율이나 제로데이 발견 성능을 의미하지 않습니다. `--min-recall`과 `--max-false-positive-cases`로 자동 회귀 기준을 설정할 수 있습니다.
