FROM python:3.11-slim

WORKDIR /app

# 国内镜像加速 + 系统依赖
ENV PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_DEFAULT_TIMEOUT=120

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# data/ 由 volume 挂载，容器内预创建
RUN mkdir -p /app/data/covers

EXPOSE 8091

CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8091"]
