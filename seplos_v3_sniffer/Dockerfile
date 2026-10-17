ARG BUILD_FROM
FROM $BUILD_FROM

RUN pip3 install --no-cache-dir paho-mqtt==2.1.0

COPY seplos_v3_sniffer.py /app/seplos_v3_sniffer.py
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
