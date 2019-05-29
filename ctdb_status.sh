#!/bin/bash
CTDB_LOG_FILE=/var/log/log.ctdb
CTDB_LOG_STATUS=/var/log/log.ctdb_status
CTDB_LOCK_FILE=/cluster2/ctdb/lockfile
CTDB_NODES=/etc/ctdb/nodes
CTDB_PUBLIC_ADDRESS=/etc/ctdb/public_addresses
date_start=`date "+%Y-%m-%d %H:%M:%S"`
echo -e $date_start >>$CTDB_LOG_STATUS

unhealthy_restart_num=0
pub_ip_restart_num=0
non_master_restart_num=0

ctdb_xpnn=$(ctdb pnn | tr -cd "[0-9]")
ctdb_recmaster=$(ctdb recmaster)

check_ctdb_start() {
    if [[ -n "ps -aux | grep -v grep | grep '/usr/sbin/ctdbd'" ]]
    then
        echo true
    else
        echo false
    fi
}

check_if_master() {
    if $(check_ctdb_start)
    then
        if [[ $ctdb_xpnn -eq $ctdb_recmaster ]] 
        then
            echo true
        else
            echo false
        fi
    fi
}

get_pub_addr_status() {
    pub_ip_status=$(ctdb status | grep "pnn:$(ctdb ipinfo $1 | grep 'CurrentNode:' | awk -F : '{print $2}')" | awk '{print $3}')
    echo $pub_ip_status
}

get_current_nodes_ip() {
    ips=$(/usr/sbin/ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}')
    echo $ips
}

get_public_address() {
    pub_ip=$(cat $CTDB_PUBLIC_ADDRESS | awk -F / '{print $1}')
    echo $pub_ip
}

need_currentnode_restart() {
    if $(check_ctdb_start)
    then
        # public ip on currentnode that we don't have to restart currentnode, avoid to providing some other problem
        if [[ $(ctdb recmaster) -eq $(ctdb pnn | awk -F : '{print $2}') ]]
        then
            return 0
        #  avoid down node to restart ctdb
        #elif [[ $(ctdb status | grep 'pnn:$(ctdb recmater)' | awk '{print $3}') == 'OK' ]]
        elif [[ -n $(ctdb status | grep "BANNED|UNHEALTHY|INACTIVE (THIS NODE)") ]] 
        then
            echo "$(date)[FILE: $0, LINE: $LINENO] current node is down node">>$CTDB_LOG_STATUS
            return 1
        fi
    fi

    return 0
}

while true
do
# check digioceanfs ctdb service has been started and lockfile 
if [[ -e "$CTDB_LOCK_FILE" ]] && ps aux | grep  digioceanfs | grep 'volfile-id=/ctdb ' | grep -q '/cluster2/ctdb$'
then
    ips=$(get_current_nodes_ip)
    # pub_ip=$(get_public_address)
    # echo "nodes_ip:$ips pub_ip:$pub_ip" >>$CTDB_LOG_STATUS
    # we have to restart ctdb if the recovery master node restart and current ip is public ip address.(bug : recovery master node restart)
    for ip_info in $ips
    do
        #echo "ip_info: $ip_info----------">>$CTDB_LOG_STATUS
        if [[ "x$(grep  $ip_info $CTDB_PUBLIC_ADDRESS)" != "x" ]]
        then
            sleep 30
            #echo "[LINE:$LINENO] ip is ctdb's public address">>$CTDB_LOG_STATUS
            if $(check_if_master) && [[ $(ctdb status | grep -c "DISCONNECTED|UNHEALTHY|INACTIVE") -eq $((`cat $CTDB_NODES | wc -l`-1)) ]] # down node
            then
                # do nothing and exit
                break
            else
                if [ $pub_ip_restart_num -lt 10 ]
                then
                    systemctl restart ctdb &>>$CTDB_LOG_STATUS
                    if [[ $? -eq 0 ]]
                    then
                        sleep 90
                        if [[ $(ctdb status | grep -c "OK") -eq $((`cat $CTDB_NODES | wc -l`)) ]]
                        then                
                            echo "$(date) [FILE: $0, LINE: $LINENO] pub ip has been setted to interfaces: ctdb restart successfully">>$CTDB_LOG_STATUS
                            pub_ip_restart_num=0
                        else
                            pub_ip_restart_num=`expr $pub_ip_restart_num + 1`
                            echo "$(date) [FILE: $0, LINE: $LINENO] pub ip has been setted to interfaces: ctdb restart failed">>$CTDB_LOG_STATUS
                        fi

                    fi
                    continue
                fi
            fi
        fi
    done

    need_currentnode_restart
    if [[ $? -eq 1 ]]
    then 
        if [[ $non_master_restart_num -lt 10 ]]
        then
            systemctl restart ctdb &>>$CTDB_LOG_STATUS
            if [[ $? -eq 0 ]]
            then
                sleep 60
                if [[ $(ctdb status | grep -c "OK") -eq $((`cat $CTDB_NODES | wc -l`)) ]]
                then                
                    echo "$(date) [FILE: $0, LINE: $LINENO] non master node down: ctdb restart successfully">>$CTDB_LOG_STATUS
                    non_master_restart_num=0
                else
                    non_master_restart_num=`expr $non_master_restart_num + 1`
                    echo "$(date) [FILE: $0, LINE: $LINENO] non master node down: ctdb restart failed">>$CTDB_LOG_STATUS
                fi

            fi
        fi
    fi

    # we have to restart ctdb if master status is ok and others are unhealthy (bug: reboot all nodes)
    if $(check_if_master) && [[ -n $(ctdb status | grep  "OK (THIS NODE)") ]] && [[ $(ctdb status | grep -v "DISCONNECTED|UNHEALTHY|INACTIVE" | grep -c "UNHEALTHY") -eq $((`cat $CTDB_NODES | wc -l`-1)) ]] \
        && [[ $(ctdb status | grep -c "lmaster") -eq $((`cat $CTDB_NODES | wc -l`)) ]]
    then
        if [[ $unhealthy_restart_num -lt 10 ]]
        then
            ctdb status &>>$CTDB_LOG_STATUS
            systemctl restart ctdb &>>$CTDB_LOG_STATUS
            if [[ $? -eq 0 ]]
            then
                sleep 60
                if [[ $(ctdb status | grep -c "OK") -eq $((`cat $CTDB_NODES | wc -l`)) ]]
                then                
                    echo "$(date) [FILE: $0, LINE: $LINENO] reboot all node: ctdb restart successfully">>$CTDB_LOG_STATUS
                    unhealthy_restart_num=0
                else
                    unhealthy_restart_num=`expr $unhealthy_restart_num + 1`
                    echo "$(date) [FILE: $0, LINE: $LINENO] reboot all node: ctdb restart failed">>$CTDB_LOG_STATUS
                fi
            fi
            continue
        fi
    fi

    sleep 5
else
    sleep 10
fi

done

