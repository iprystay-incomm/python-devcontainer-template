FROM python:3.10

ARG USERNAME=nonroot
RUN apt update && \
    apt install -y sudo \
    echo "${USERNAME} ALL=(ALL)       NOPASSWD: ALL" | EDITOR='tee -a' visudo

# Add non-root user
RUN groupadd --gid 1000 ${USERNAME} && \
    useradd --uid 1000 --gid 1000 -m ${USERNAME}
## Make sure to reflect new user in PATH
ENV PATH="/home/${USERNAME}/.local/bin:${PATH}"
USER ${USERNAME}

## Pip dependencies
# Upgrade pip
RUN pip install --upgrade pip
# Install dependencies
COPY --chown=${USERNAME}:1000 python-requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

