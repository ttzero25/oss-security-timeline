# 오픈소스 보안 타임라인

## 프로젝트 목적

GitHub 오픈소스 저장소의 변경과 공개 취약점 공지를 한 시간축에 모아, 어떤 저장소와 패키지에 보안 이슈가 집중됐는지 확인합니다. 코드 조사에서는 미공개 취약점의 **가설**을 만들고, 실제 코드와 PoC로 검증된 결과만 비공개 GHSA 제보 초안과 CVE 요청 브리프로 정리합니다.

## 한눈에 보기

- GitHub 릴리스·커밋, 저장소 보안 공지, 패키지별 검토/미검토 GHSA 및 OSV 기록을 수집합니다.
- CVE/GHSA 별칭을 같은 공지로 묶고, 게시·수정·최초 관측 시각을 저장해 타임라인과 저장소·패키지 순위를 만듭니다.
- 공개 변경 메시지와 Python·JavaScript/TypeScript 코드에서 검토 후보를 찾습니다. 후보는 취약점이나 제로데이 확정 결과가 아닙니다.
- 완성된 PoC를 정상 입력과 공격 입력으로 비교한 뒤, 코드 경로·영향·기존 공지 중복 여부가 검토된 경우에만 제보 **초안**을 생성합니다. 외부 제출과 CVE/GHSA 번호 부여는 자동으로 하지 않습니다.
- 로컬 웹에서 타임라인, 에이전트 역할, 코드 조사 현황을 확인할 수 있습니다.

Python 3.11 이상이 필요합니다. 기본 CLI와 웹 화면에는 추가 Python 패키지가 필요하지 않습니다. 공개 GitHub API도 인증 없이 접근할 수 있지만, 여러 저장소를 반복 수집할 때는 읽기용 `GITHUB_TOKEN`을 권장합니다. PoC의 기본 격리 실행에는 Docker 데몬과 미리 준비된 컨테이너 이미지가 필요합니다.

## 신규 팀원을 위한 빠른 시작

1. 비공개 저장소 접근 권한을 받은 뒤 프로젝트를 복제합니다.

   ```sh
   git clone https://github.com/ttzero25/oss-security-timeline.git
   cd oss-security-timeline
   python3 --version
   ```

2. 읽기용 GitHub 토큰을 환경 변수로 제공하고 샘플 저장소를 한 페이지씩 수집합니다. 이 첫 실행은 동작 확인용으로, 커밋 전수 수집은 아닙니다.

   ```sh
   export GITHUB_TOKEN=YOUR_READ_ONLY_GITHUB_TOKEN
   python3 -m oss_timeline sync https://github.com/lodash/lodash --max-pages 1 --max-manifests 10
   python3 -m oss_timeline report --format html --output data/report.html
   ```

3. 웹 화면을 실행하고 브라우저에서 [http://127.0.0.1:8765/](http://127.0.0.1:8765/)을 엽니다. `/agents`는 역할 구성, `/research`는 코드 조사 현황입니다. 서버는 `127.0.0.1`에만 바인딩하며 읽기 요청만 처리합니다.

   ```sh
   python3 tools/web.py --port 8765
   ```

4. 다른 터미널에서 회귀 검사를 실행합니다.

   ```sh
   python3 -m unittest discover -s tests
   ```

실제 조사에서는 `--max-pages`와 `--max-manifests`를 필요에 맞게 늘리고, 출력의 `coverage`와 `warnings`를 확인하세요. `python3 -m oss_timeline watch https://github.com/owner/repo --interval-hours 6`으로 정기 관측할 수 있습니다. 운영 중 문제가 생기면 [troubleshooting](troubleshooting/README.md)을 먼저 확인하세요.

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
| [tools](tools/README.md) | CLI 안내와 읽기 전용 로컬 웹 도구 |
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
