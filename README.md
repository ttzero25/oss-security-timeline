# 오픈소스 보안 타임라인

## 프로젝트 목적

GitHub 오픈소스 저장소의 변경과 공개 취약점 공지를 한 시간축에 모아, 어떤 저장소와 패키지에 보안 이슈가 집중됐는지 확인합니다. 코드 조사에서는 미공개 취약점의 **가설**을 만들고, 실제 코드와 PoC로 검증된 결과만 비공개 GHSA 제보 초안과 CVE 요청 브리프로 정리합니다.

## 한눈에 보기

- GitHub 릴리스·커밋, 저장소 보안 공지, 패키지별 검토/미검토 GHSA 및 OSV 기록을 수집합니다.
- CVE/GHSA 별칭을 같은 공지로 묶고, 게시·수정·최초 관측 시각을 저장해 타임라인과 저장소·패키지 순위를 만듭니다.
- 실험실의 보안 공지 표에는 GHSA/원본 식별자와 등록된 CVE를 별도 칸에 표시하고, 공지 원문에 명시된 CWE 유형만 보여줍니다.
- 실험실은 공지의 영향 버전과 패치 버전을 비교하고, 공지가 같은 저장소의 커밋을 직접 참조하면 삭제·추가된 코드 줄을 나란히 보여줍니다. 이 참조만으로 해당 커밋이 완전한 fix라고 판정하지 않습니다.
- 공개 변경 메시지와 Python·JavaScript/TypeScript·C/C++ 코드에서 검토 후보를 찾습니다. C/C++는 외부 입력이 셸 실행, 비상수 포맷 문자열, 위험 문자열 복사로 이어지는 보수적 패턴만 다룹니다. 후보는 취약점이나 제로데이 확정 결과가 아닙니다.
- 완성된 PoC를 정상 입력과 공격 입력으로 비교한 뒤, 코드 경로·영향·기존 공지 중복 여부가 검토된 경우에만 제보 **초안**을 생성합니다. 외부 제출과 CVE/GHSA 번호 부여는 자동으로 하지 않습니다.
- 로컬 웹의 Home에서 누적 탐지와 에이전트 역할을, 실험실에서 저장소별 조사 상태를, 정리에서 OSS별 요약을 확인할 수 있습니다.

Python 3.11 이상이 필요합니다. 기본 CLI와 웹 화면에는 추가 Python 패키지가 필요하지 않습니다. 웹은 `GITHUB_TOKEN`이 없으면 설치·로그인된 GitHub CLI의 인증을 메모리에서만 활용합니다. 어느 쪽도 없으면 비인증 API 한도가 적용되므로 읽기용 토큰을 권장합니다. PoC의 기본 격리 실행에는 Docker 데몬과 미리 준비된 컨테이너 이미지가 필요합니다.

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

3. 웹 화면을 실행하고 브라우저에서 [http://127.0.0.1:8765/](http://127.0.0.1:8765/)을 엽니다. 실험실에서 `https://github.com/owner/repo` 형식의 링크를 입력하면 공개 공지 수집과 정적 코드 조사를 백그라운드에서 시작합니다. Home은 누적 수치, 정리는 OSS별 결과입니다. 서버는 `127.0.0.1`에만 바인딩합니다.

   ```sh
   python3 tools/web.py --port 8765
   ```

4. 다른 터미널에서 회귀 검사를 실행합니다.

   ```sh
   python3 -m unittest discover -s tests
   ```

웹은 한 번에 한 저장소를 조사하며 API 페이지와 매니페스트를 각각 최대 100개, 공지 참조 커밋은 최대 5개까지 읽습니다. 두 번째 수집부터는 마지막 관측 시각 이후 커밋만 요청해 API 사용량을 줄이되, 첫 수집에서 잘린 과거 이력은 완료로 오인하지 않고 경고를 유지합니다. 조사 완료 뒤 실험실의 수집 범위와 경고를 확인하세요. CWE와 참조 커밋 비교는 새 수집부터 채워지므로 기존 저장소는 다시 수집해야 합니다. 더 세밀한 범위 설정과 정기 관측에는 CLI의 `sync`·`watch`를 사용합니다. 문제가 생기면 [troubleshooting](troubleshooting/README.md)을 먼저 확인하세요.

## 코드 조사와 제보 흐름

`python3 -m oss_timeline audit https://github.com/owner/repo`는 공개 저장소의 최신 커밋을 새 로컬 디렉터리에 복제해 코드 가설을 `data/research/`에 기록합니다. 로컬 체크아웃은 `python3 -m oss_timeline audit /path/to/checkout --repo owner/repo`로 조사할 수 있습니다. 출력된 `audit.json`에서 후보 ID와 조사 범위를 확인합니다.

후보가 남으면 `poc-init`으로 `proof.py`, `manifest.json`, `claim.example.json`을 준비합니다. 조사한 커밋의 **실제 앱 경로**를 호출하도록 PoC를 완성하고, 정상 입력 대조군과 보안 영향을 명시한 `claim.json`을 작성하세요. `poc-verify`는 기본적으로 네트워크가 없는 읽기 전용 컨테이너에서 두 입력을 실행합니다. `--local`은 신뢰할 수 있는 테스트 코드에만 사용합니다. 재현 결과와 코드 인용이 같은 커밋에 맞고, 기존 공지 조사 근거가 채워지면 `disclosure`가 `GHSA_CANDIDATE.md`와 `CVE_REQUEST_BRIEF.md`를 만듭니다.

```sh
python3 -m oss_timeline poc-init path/to/audit.json FIND-XXXXXXXXXXXX
python3 -m oss_timeline poc-verify path/to/FIND-XXXXXXXXXXXX/manifest.json
python3 -m oss_timeline disclosure path/to/audit.json FIND-XXXXXXXXXXXX \
  --claim path/to/FIND-XXXXXXXXXXXX/claim.json \
  --evidence path/to/FIND-XXXXXXXXXXXX/evidence.json
```

두 파일은 로컬의 비공개 제출용 초안입니다. 보고 전 코드 경로와 PoC가 같은 문제를 입증하는지 사람이 검토하고, [GitHub 비공개 취약점 제보](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately) 또는 프로젝트 보안 정책을 따르세요. CVE 번호는 [관리자 또는 해당 CNA 절차](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories)에 따라 요청합니다.

## 프로젝트 구조

| 위치 | 내용 |
| --- | --- |
| [agents](agents/README.md) | 7개 역할별 입력·출력과 실행 흐름 |
| [tools](tools/README.md) | CLI 안내와 로컬 수집·조회 웹 도구 |
| [rules](rules/README.md) | 코드 탐지, PoC 검증, 비공개 제보 기준 |
| [troubleshooting](troubleshooting/README.md) | API 제한·Docker·수집 누락 등의 해결 방법 |
| `oss_timeline/` | 실행 코드와 SQLite 저장·보고서 생성 |
| `tests/` | 수집·중복 제거·PoC·제보 게이트 회귀 검사 |
| `data/` | 실행 중 생성되는 DB, 복제본, PoC, 비공개 초안; Git 제외 |

공개 데이터 흐름은 `InventoryAgent → (ChangeAgent + AdvisoryAgent 병렬) → CandidateAgent`입니다. 코드 조사 흐름은 `SourceScanAgent → PocValidatorAgent → DisclosureAgent`입니다. 이 역할들은 현재 결정적인 Python 모듈이며 독립적으로 판단하는 LLM 에이전트는 아닙니다.

## 결과를 해석할 때

“전수”는 접근 가능한 공개 API 페이지와 설정한 수집 상한 안에서의 전수를 뜻합니다. 기본 브랜치 밖의 커밋, 삭제된 과거 패키지, CVE 전체 등록부의 모든 항목은 포함되지 않을 수 있습니다. API 실패·페이지 제한·Git 트리 잘림은 결과의 `coverage`와 `warnings`에 표시됩니다. 공지 수정 이력은 정기 관측을 시작한 시점부터 기록합니다.

수치 예측은 과거 **공개 보안 공지 게시 건수**로 향후 12개월을 추정합니다. 공개 공지 5건과 관측 기간 24개월 미만이면 산출하지 않으며, 관측할 수 없는 미공개 제로데이 발생 수는 예측하지 않습니다. 코드 스캔의 빈 결과도 안전성의 증거가 아닙니다.

데이터 원천: [GitHub 저장소 보안 공지 API](https://docs.github.com/en/rest/security-advisories/repository-advisories), [GitHub 글로벌 보안 공지 API](https://docs.github.com/en/rest/security-advisories/global-advisories), [GitHub Git Trees API](https://docs.github.com/en/rest/git/trees), [OSV](https://osv.dev/).
