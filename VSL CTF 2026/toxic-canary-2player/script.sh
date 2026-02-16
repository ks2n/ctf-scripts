for i in $(seq 1 100); do
  echo "===== RUN $i =====" >> text.txt

  # chạy tối đa 2 giây, quá thì kill
  timeout 2s python solve.py REMOTE 14.225.212.104 9009 >> text.txt 2>&1

  # ghi trạng thái nếu bị timeout
  if [ $? -eq 124 ]; then
    echo "[!] TIMEOUT (2s) -> next run" >> text.txt
  fi
done
