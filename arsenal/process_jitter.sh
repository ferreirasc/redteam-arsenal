# Autor: Leonardo Ferreira

# Extract jitter information from iperf server output ("-y" option) 
# and calculate the average of all jitter values in a folder.

#!/bin/bash

# Directory of iperf logs
DIRECTORY="Jitter/"
sum=0

main()
{
	cd $DIRECTORY
	mkdir jitter_fmt

	# Formating...	
	for i in `find . -maxdepth 1 -type f -printf '%f\n'`
	do
		cat $i | cut -d ',' -f 10 | head -n -1 > tmpfile
        	cat tmpfile > jitter_fmt/${i}_tmp
		rm tmpfile
	done
	
	# Process...
	cd jitter_fmt/	
	num_line=`wc -l < ${i}_tmp`
	for i in `seq $num_line`
	do
		echo "LINE: $i"
		sum=0
		lines=0
		for j in `ls`
		do
			echo "FILE: $j"
			value=`sed --quiet "${i}p" $j`
			if [[ $value ]] 
			then
				sum=`echo "$sum + $value" | bc`
				lines=$(($lines + 1))
			fi
		done
		echo "scale=4;$sum/$lines" | bc | awk '{printf "%.3f\n", $0}' >> ../tmpfile
	done

	# Enumerate...
	lines=`wc -l < ../tmpfile`	
	for j in `seq $lines`
	do
		echo $j >> numbers
	done
	paste numbers ../tmpfile > jitter_plot -d ,

	# Clean
	rm ../tmpfile a*_tmp numbers
}

main '$@'
