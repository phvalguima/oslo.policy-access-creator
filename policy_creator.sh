#!/bin/bash

function check_if_uuid_on_url {
	for part in $(echo "$1" | sed 's/\// /g'); do
		# Some IDs at OS come as a single string of chars, like user's and project's IDs
		# The majority, however, follow the pattern: XXXXXXXX-XXXX-XXXX-XXXXXXXXXXXX
		# We will search for both
		if [[ $part =~ ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$ ]] || [[ $part =~ ^[a-fA-F0-9]{28} ]]; then 
			url_uuid=$part
			return 0
		fi
	done
	url_uuid=
}

## CHECK ARGUMENTS RECEIVED
while test $# -gt 0; do
	case "$1" in
		-h|--help)
			echo "policy_creator.sh - generate access json file in format similar to"
			echo "https://github.com/openstack/oslo.policy/blob/master/sample_data/auth_v3_token_admin.json"
			echo "Final result is echoed on terminal"
			echo " "
			echo "options:"
			echo "-h|-help		show this help"
			echo "-f|--filerc FILEPATH	pass path and name of rc file with OS credentials"
			echo "-s|--services a,b,c	comma-separated list of OS services to offer as endpoints"
			echo "			default services currently considered are:"
			echo "			cinderv3 neutron heat cinderv2 designate nova gnocchi aodh placement swift heat-cfn glance keystone"
			echo "-r|--region REGION	OS region name to retrieve endpoints"
			echo "-w|--write FILEPATH	filepath to write output"
			exit 0
			;;
		-f|--filerc)
			shift
			if test $# -gt 0; then
				export filerc=$1
				if [ ! -f $filerc ]; then echo "No rc file found on specified -f location"; exit 1; fi
			else
				echo "No novarc specified, exiting..."; exit 1;
			fi
			shift
			;;
		-s|--services)
			shift
                        if test $# -gt 0; then
                                export services=$(echo "$1" | sed "s/,/ /g")
                        fi
			shift
			;;
		-r|--region)
			shift
			if test $# -gt 0; then
                                export region_name=$1
                        fi
			shift
			;;
		-w|--write)
			shift
			if test $# -gt 0; then
				export final_result=$1
			fi
			shift
			;;
		*)
			echo "Unrecognized option, ignoring"
			exit 1
			;;
	esac
done

if [ -z "$filerc" ]; then
	echo "No rc file specified with OS credentials, looking for local novarc..."
	if [ ! -f ./novarc ]; then
		echo "local novarc file not present, exiting"
		exit 1
	fi
	. novarc
else
	. $filerc
fi
if [ -z "$region_name" ]; then
	region_name="RegionOne"
fi
if [ -z "$services" ]; then
	services="cinderv3 neutron heat cinderv2 designate nova gnocchi aodh placement swift heat-cfn glance keystone"
fi
if [ -z "$final_result" ]; then
	final_result="/tmp/final_access.json"
fi
############################################


# Now the actual script
# we will use some /tmp files for jq
openstack catalog list -f json > /tmp/catalog.file
openstack endpoint list -f json > /tmp/endpoint.file
sed -i 's/\$(tenant_id)s//g' /tmp/endpoint.file

rm endpoint_result.file
touch endpoint_result.file

for svc in $services; do
	touch /tmp/endpoint_result.file
	echo "Processing service $svc..."
	# Taking admin URL from openstack catalog
	admin=$(jq --arg svc $svc -M 'map(select(.Name == $svc)) | .[].Endpoints' /tmp/catalog.file | awk -F"admin: " '{print $2}' | awk -F"\\" '{print $1}')
	# Some urls come with project UUID.
	# The main issue is that openstack endpoint list does not use UUID urls
	# So, to find which URL from catalog corresponds to which on endpoint list
	# we must take UUID out, find it and then add again
	check_if_uuid_on_url $admin
	if [ ! -z $url_uuid ]; then
		admin=$(echo $admin | awk -F"${url_uuid}" '{print $1}')
		uuid_and_url=$(echo "$admin$url_uuid")
	        # Getting URL-specific info from openstack endpoint and taking unnecessary fields out
		# adding the UUID back
	        admin_json=$(jq --arg url $admin --arg uuid_and_url $uuid_and_url -M 'map(select(.URL == $url)) | del(.[0].Enabled) | del(.[0]."Service Type") | del(.[0]."Service Name") | . [0] | .URL=$uuid_and_url' /tmp/endpoint.file)
	else
		# Getting URL-specific info from openstack endpoint and taking unnecessary fields out
		admin_json=$(jq --arg url $admin -M 'map(select(.URL == $url)) | del(.[0].Enabled) | del(.[0]."Service Type") | del(.[0]."Service Name") | . [0]' /tmp/endpoint.file)
	fi
	# This temp file contains all info and will be added to final json later
	echo "$admin_json" >> /tmp/endpoint_result.file


	# Doing same thing for public and internal
	public=$(jq --arg svc $svc -M 'map(select(.Name == $svc)) | .[].Endpoints' /tmp/catalog.file | awk -F"public: " '{print $2}' | awk -F"\\" '{print $1}')
        check_if_uuid_on_url $public
        if [ ! -z $url_uuid ]; then
                public=$(echo $public | awk -F"${url_uuid}" '{print $1}')
                uuid_and_url=$(echo "$public$url_uuid")
	        public_json=$(jq --arg url $public --arg uuid_and_url $uuid_and_url -M 'map(select(.URL == $url)) | del(.[0].Enabled) | del(.[0]."Service Type") | del(.[0]."Service Name") | . [0] | .URL=$uuid_and_url' /tmp/endpoint.file)
	else
	        public_json=$(jq --arg url $public -M 'map(select(.URL == $url)) | del(.[0].Enabled) | del(.[0]."Service Type") | del(.[0]."Service Name") | . [0]' /tmp/endpoint.file)
	fi
	echo "$public_json" >> /tmp/endpoint_result.file
	# Now internal
        internal=$(jq --arg svc $svc -M 'map(select(.Name == $svc)) | .[].Endpoints' /tmp/catalog.file | awk -F"internal: " '{print $2}' | awk -F"\\" '{print $1}')
        check_if_uuid_on_url $internal
        if [ ! -z $url_uuid ]; then
                internal=$(echo $internal | awk -F"${url_uuid}" '{print $1}')
                uuid_and_url=$(echo "$internal$url_uuid")
                # Getting URL-specific info from openstack endpoint and taking unnecessary fields out
                # adding the UUID back
	        internal_json=$(jq --arg url $internal --arg uuid_and_url $uuid_and_url -M 'map(select(.URL == $url)) | del(.[0].Enabled) | del(.[0]."Service Type") | del(.[0]."Service Name") | . [0] | .URL=$uuid_and_url' /tmp/endpoint.file)
	else
	        internal_json=$(jq --arg url $internal -M 'map(select(.URL == $url)) | del(.[0].Enabled) | del(.[0]."Service Type") | del(.[0]."Service Name") | . [0]' /tmp/endpoint.file)
	fi
	echo "$internal_json" >> /tmp/endpoint_result.file
	result=$(jq -s "." < /tmp/endpoint_result.file)
	openstack catalog show $svc -f json > /tmp/catalog.svc.file
	endpoint_result=$(jq --argjson endpoint "$result" '.endpoints=$endpoint' /tmp/catalog.svc.file)
	echo "$endpoint_result" >> endpoint_result.file

	rm /tmp/endpoint_result.file
done

user=$(openstack user list -f json --long | jq --arg OS_USERNAME $OS_USERNAME -M 'map(select(.Name==$OS_USERNAME)) | . [0]')
# take out " as this bugs jq on next line
domain=$(echo "$user" | jq -M '.Domain' | sed "s/\"//g");
domain=$(openstack domain list -f json | jq --arg domain_id $domain -M 'map(select(.ID==$domain_id)) | . []');
user=$(echo "$user" | jq --argjson domain "$domain" -M '.Domain=$domain');
#echo "User json: $user"

if [[ ! -z $OS_PROJECT_NAME ]]; then
	project=$(openstack project list -f json --long | jq --arg name $OS_PROJECT_NAME -M 'map(select(.Name==$name)) | . [0]')
elif [[ ! -z $OS_PROJECT_ID ]]; then
	project=$(openstack project list -f json --long | jq --arg name $OS_PROJECT_ID -M 'map(select(.ID==$id)) | . [0]')
else
	project=$(openstack project list -f json --my-projects --long | jq -M '.[0]')
fi
domain=$(echo "$project" | jq -M '."Domain ID"' | sed "s/\"//g");
domain=$(openstack domain list -f json | jq --arg domain_id $domain -M 'map(select(.ID==$domain_id)) | . []');
project=$(echo "$project" | jq --argjson domain "$domain" -M '."Domain ID"=$domain');
#echo "Project json: $project"

endpoints=$(cat endpoint_result.file)
echo "Loading Endpoints intermediary file...."
echo "{ \"token\": {\"methods\": [\"password\"],\"expires_at\": \"2038-01-18T21:14:07Z\",\"issued_at\": \"$(date +%FT%TZ)\"} }" > $final_result
echo $(jq --slurpfile endpoints endpoint_result.file '.catalog=$endpoints' $final_result) > $final_result
echo $(jq --argjson user "$user" -M '.user=$user' $final_result) > $final_result
echo $(jq --argjson project "$project" -M '.project=$project' $final_result) > $final_result

echo "Token created:"
cat $final_result | jq .
