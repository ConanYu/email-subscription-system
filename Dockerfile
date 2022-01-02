FROM python:3.10.1-bullseye

ENV GOODGUY=/home/goodguy

ENV PYTHONPATH=$GOODGUY

RUN mkdir $GOODGUY

WORKDIR $GOODGUY

COPY ./ $GOODGUY

RUN pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
