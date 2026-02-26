for buffer in radio events main system crash kernel; do
    echo ""
    echo "=========================================="
    echo "Testing buffer: $buffer"
    echo "=========================================="
    
    # 清除舊檔案
    rm -f /data/local/tmp/logcat_${buffer}.txt
    
    # 嘗試抓取 logcat
    echo "Command: logcat -b $buffer -T '$TEST_TIME' -d > /data/local/tmp/logcat_${buffer}.txt"
    logcat -b $buffer -T "$TEST_TIME" -d > /data/local/tmp/logcat_${buffer}.txt 2>&1
    EXIT_CODE=$?
    echo "Exit code: $EXIT_CODE"
    
    # 檢查檔案是否存在
    if [ -f /data/local/tmp/logcat_${buffer}.txt ]; then
        FILE_SIZE=$(wc -c < /data/local/tmp/logcat_${buffer}.txt)
        echo "File created: YES"
        echo "File size: $FILE_SIZE bytes"
        
        # 檢查是否有 "cp failed" 錯誤
        CP_FAILED=$(grep "cp failed" /data/local/tmp/logcat_${buffer}.txt 2>/dev/null | head -1)
        if [ -n "$CP_FAILED" ]; then
            echo "⚠️ Found 'cp failed' error:"
            echo "$CP_FAILED"
        fi
        
        # 顯示前 5 行內容
        echo "First 5 lines:"
        head -5 /data/local/tmp/logcat_${buffer}.txt
        
        # 最終判斷
        if [ $FILE_SIZE -eq 0 ]; then
            echo "❌ Result: EMPTY FILE"
        elif [ -n "$CP_FAILED" ]; then
            echo "❌ Result: CP FAILED ERROR"
        else
            echo "✅ Result: SUCCESS"
        fi
    else
        echo "File created: NO"
        echo "❌ Result: FILE NOT CREATED"
    fi
    
    echo ""
done

echo "=========================================="
echo "Test complete!"
echo "=========================================="
