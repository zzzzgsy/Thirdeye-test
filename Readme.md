**PRs are highly welcome**

 - Don't hesitate to open new issues for any question/issue to discuss.
   This tool has created for Android 12 on pixel devices primarily.
  -   However, it can easily be adopted for other Android versions or
   vendors by modifying `device.py`. Mostly, window and activity
   variables need to be changed for other platforms.
   - Documentation and
   usage instructions will be published soon


-----
```
flame:/ # mkdir /data/crontab
flame:/ # echo '* * * * * svc wifi enable' >> /data/crontab/root
flame:/ # echo '* * * * * settings put global airplane_mode_on 0' >> /data/crontab/root
flame:/ # echo 'crond -b -c /data/crontab' > /data/adb/service.d/crond.sh
flame:/ # chmod +x /data/adb/service.d/crond.sh
settings put global captive_portal_mode 0 

adb shell content insert --uri content://settings/system --bind name:s:accelerometer_rotation --bind value:i:0
```
