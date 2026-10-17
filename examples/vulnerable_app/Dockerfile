# SPDX-License-Identifier: Apache-2.0
# Deliberately flawed demo image for the OmniSeek examples.
FROM python:latest
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
