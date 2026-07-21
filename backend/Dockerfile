FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# entrypoint.sh を実行権限付きでコピー
# → コンテナ起動時に resolv.conf へ "options no-aaaa" を追加し
#   DNS レベルで IPv6 (AAAA) クエリを遮断する
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
