[Railway 서버 배포/업데이트 상세 가이드]

1) GitHub 업로드
- 이 폴더(server_storeapp_api_fastapi)만 새 레포로 업로드 추천

2) Railway 배포
- Railway -> New Project -> Deploy from GitHub Repo
- 배포 후 Variables(환경변수) 설정:
  SUPERADMIN_ID = dldydtjq159
  SUPERADMIN_PW = tkfkd4026
  TOKEN_SECRET  = 32자 이상 랜덤 문자열

  (업데이트 체크용)
  LATEST_VERSION = 1.0.1
  VERSION_NOTES  = 변경내용
  DOWNLOAD_URL   = 최신 파일 링크

3) Volume(관리자 계정 유지 필수)
- Railway -> Add Volume
- Mount Path: /data
- DB_PATH 기본값: /data/storeapp.db

4) 테스트
- https://<railway주소>.up.railway.app/storeapp/v1/version
- https://<railway주소>.up.railway.app/storeapp/v1/auth/login

5) 업데이트
- GitHub에 push하면 Railway가 자동 재배포
