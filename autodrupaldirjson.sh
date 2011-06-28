#!/bin/bash

#If in doubt about MYSQL_HOST, try '127.0.0.1'.
MYSQL_HOST="1.2.3.4"
MYSQL_USER="someuser"
MYSQL_PASS="somepass"
MYSQL_DB="somedb"
AUTODRUPALDIR=$(/bin/pwd)/autodrupaldirjson

## You shouldn't have to modify anything below this line.

export MYOPTS="-h $MYSQL_HOST -p$MYSQL_PASS -u $MYSQL_USER $MYSQL_DB"
export FUSEOPTS="-H $MYSQL_HOST -p $MYSQL_PASS -u $MYSQL_USER -D $MYSQL_DB"

for table in $(mysql $MYOPTS -e 'show tables' | sed '1d')
  do PRIKEY=$(mysql $MYOPTS -e 'show create table '$table'\G' | grep -F 'PRIMARY KEY')

  # We don't currently handled multiple primary keys; synthesize those by hand.
  echo $PRIKEY | sed 's/,$//' | grep -qF ',' && continue

  PRIKEY=$(echo $PRIKEY | sed 's/`).*//;s/PRIMARY KEY...//')
  echo $table: $PRIKEY

  #Unmount anything that was there, just in case.
  umount $AUTODRUPALDIR/$table >>/dev/null 2>&1

  mkdir -p $AUTODRUPALDIR/$table

  ./dfuse $FUSEOPTS -t $table -P $PRIKEY -c '*' --json $AUTODRUPALDIR/$table
  sleep 0.25
done 
