# 오픈소스 보안 타임라인

공개 GitHub 저장소 URL을 입력해 릴리스·커밋·저장소 보안 공지·패키지별 GitHub 검토/미검토 및 OSV 공지를 수집하고, 시각별 타임라인과 저장소·패키지 순위를 만듭니다. Python 3.11 이상이며 추가 패키지는 필요하지 않습니다.

```sh
cd /Users/ty/oss-security-timeline
export GITHUB_TOKEN=YOUR_READ_ONLY_GITHUB_TOKEN
python3 -m oss_timeline sync https://github.com/owner/repo https://github.com/another/repo
python3 -m oss_timeline report --format html --output data/report.html
python3 -m oss_timeline report --format json --output data/report.json
```

6시간마다 계속 관측하려면 `python3 -m oss_timeline watch https://github.com/owner/repo --interval-hours 6`을 실행합니다. 종료는 Ctrl-C입니다.

## 미공개 취약점 조사와 비공개 제보 초안

`audit`는 공개 저장소를 새 디렉터리에 얕게 복제하거나 기존 로컬 체크아웃을 읽어 Python 및 JavaScript/TypeScript의 외부 입력→위험 동작 경로를 가설로 기록합니다. 현재 명령형 실행, 코드 평가, Python 역직렬화, URL 요청을 우선 조사합니다. 출력은 `data/research/<repo>/<commit>/audit.json`이며 조사한 커밋, 파일 조사 범위, 기존 타임라인 DB에 저장된 공개 공지 목록을 함께 기록합니다. 기존 DB 목록은 수집 당시의 스냅샷이므로 새 취약점 여부를 판정하는 근거로 단독 사용하지 않습니다. 정적 결과는 취약점 확정이나 제로데이 판정이 아닙니다.

```sh
python3 -m oss_timeline audit https://github.com/owner/repo
# 로컬 체크아웃을 사용할 때:
python3 -m oss_timeline audit /path/to/checkout --repo owner/repo

python3 -m oss_timeline poc-init data/research/owner_repo/<commit>/audit.json FIND-XXXXXXXXXXXX
# 생성된 proof.py의 실제 앱 호출과 정상/공격 입력을 채우고,
# claim.example.json을 claim.json으로 복사해 코드 경로·영향·중복 조사 근거를 채웁니다.
python3 -m oss_timeline poc-verify data/research/owner_repo/<commit>/FIND-XXXXXXXXXXXX/manifest.json
python3 -m oss_timeline disclosure data/research/owner_repo/<commit>/audit.json FIND-XXXXXXXXXXXX \
  --claim data/research/owner_repo/<commit>/FIND-XXXXXXXXXXXX/claim.json \
  --evidence data/research/owner_repo/<commit>/FIND-XXXXXXXXXXXX/evidence.json
```

PoC는 조사한 **동일 커밋의 실제 코드**를 호출해야 합니다. `poc-verify`는 기본적으로 네트워크·쓰기 권한을 끈 컨테이너에서 정상 입력과 공격 입력을 각각 실행하며, 공격 입력에서만 관측 마커가 나타나야 성공합니다. 컨테이너 이미지는 미리 준비해야 합니다. `--local`은 신뢰할 수 있는 테스트 코드에만 쓰는 격리 없는 실행 방식입니다. 기계적 결과만으로 보안 영향이 입증되지는 않으므로 `disclosure`는 입력 도달성, 기본 설정, 공격자 통제, 실제 영향, 상위 방어 코드, 기존 공지와 중복 여부를 적은 `claim.json`도 요구합니다.

검증을 통과하면 같은 후보 폴더에 `GHSA_CANDIDATE.md`와 `CVE_REQUEST_BRIEF.md`가 만들어집니다. 두 파일은 **비공개 제출용 초안**이며 CVE/GHSA 번호를 임의로 부여하거나 자동 제출하지 않습니다. GitHub의 [비공개 취약점 제보 절차](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)를 사용하고, CVE 번호는 [관리자 또는 해당 CNA의 절차](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories)에 따라 요청합니다. 실제 보고 전에는 코드 경로와 PoC가 같은 취약점을 입증하는지 사람이 검토해야 합니다.

토큰 없이도 공개 API가 허용하는 범위에서 실행할 수 있지만 GitHub 요청 제한이 훨씬 낮습니다. 명령은 각 레포의 수집 결과와 누락·실패 경고를 출력합니다. 반복 실행하면 최초 관측 시각(`first_seen`)을 유지하고 마지막 관측·수정 시각을 갱신합니다. 정기 수집은 위 `sync` 명령을 cron 또는 CI에서 실행하면 됩니다. 보고서는 로컬 파일입니다.

공개 데이터 파이프라인에서는 `InventoryAgent`가 기본 브랜치의 매니페스트에서 배포 패키지 이름을 찾고, `ChangeAgent`와 `AdvisoryAgent`가 동시에 변경 및 공개 공지를 수집합니다. `CandidateAgent`는 공개 변경 메시지와 최대 30개 관련 커밋의 변경 파일·패치를 근거로 검토 후보를 만듭니다. 코드 조사 파이프라인에서는 `SourceScanAgent`가 가설을 만들고, `PocValidatorAgent`가 대조군 재현 근거를 기록하고, `DisclosureAgent`가 근거가 채워진 비공개 제보 초안을 작성합니다. `forecast`는 과거 공지 게시율에서 향후 공개 공지 건수의 예측 구간을 계산합니다.

범위와 해석:

- “전수”는 접근 가능한 공개 API 페이지 전체를 뜻합니다. `--max-pages`와 `--max-manifests`를 키우면 범위를 늘릴 수 있으며 제한 도달, 트리 잘림, API 실패는 보고서에 표시됩니다. 커밋은 기본 브랜치를 대상으로 하며 CVE 전체 등록부에 대한 완전한 검색은 포함되지 않습니다.
- 패키지 매핑은 현재 기본 브랜치의 매니페스트에 기반합니다. 과거에 존재했다가 삭제된 패키지, 매니페스트가 없는 제품, 외부 패키지와 레포의 잘못된 대응 가능성은 별도 조사 대상입니다.
- 저장소 보안 공지와 글로벌 GHSA, OSV의 CVE/GHSA 별칭을 한 건으로 중복 제거합니다. 고유 공지 수는 취약점의 절대 수가 아니며 공지 수정 이력 전체는 API만으로 복원할 수 없습니다. 정기 수집부터 최초·최종 관측 시각과 관측별 공지 변경 해시를 보존합니다.
- “보안 관련 변경 후보”는 키워드 단서일 뿐 취약점이나 제로데이의 확인 결과가 아닙니다. 코드 검증과 책임 있는 보고가 필요합니다.
- 수치 예측은 공개 보안 공지의 향후 게시 건수를 위한 Gamma-Poisson 모델입니다. 최소 5건·24개월 이력이 없으면 산출하지 않습니다. 미공개 제로데이 발생 건수는 관측할 수 없으므로 숫자로 예측하지 않습니다.

데이터 원천: [GitHub 저장소 보안 공지 API](https://docs.github.com/en/rest/security-advisories/repository-advisories), [GitHub 글로벌 보안 공지 API](https://docs.github.com/en/rest/security-advisories/global-advisories), [GitHub Git Trees API](https://docs.github.com/en/rest/git/trees), [OSV API](https://osv.dev/).
