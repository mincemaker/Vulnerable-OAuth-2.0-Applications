FROM mongo:4.4
COPY mongodbdata mongodbdata
COPY seed.sh /seed.sh
RUN chmod +x /seed.sh
CMD ["/seed.sh"]
