services:
  web:
    image: defaultmart:latest
    ports:
      - "8000:8000"
    environment:
      - DB_PASSWORD={{ENV_SECRET3}}
