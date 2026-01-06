package com.emergency.datacollector

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * MCC-MNC lookup utility for getting operator brand from CSV database
 */
object MccMncLookup {
    
    private val mccMncMap = mutableMapOf<String, String>()
    private var isLoaded = false
    
    /**
     * Load the MCC-MNC database from assets
     * CSV format: MCC;MNC;PLMN;Region;Country;ISO;Operator;Brand;TADIG;Bands
     */
    fun load(context: Context) {
        if (isLoaded) return
        
        try {
            val inputStream = context.assets.open("mcc-mnc.csv")
            val reader = BufferedReader(InputStreamReader(inputStream))
            
            // Skip header line
            reader.readLine()
            
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                val parts = line!!.split(";")
                if (parts.size >= 8) {
                    val mcc = parts[0].trim()
                    val mnc = parts[1].trim()
                    val brand = parts[7].trim()
                    
                    if (mcc.isNotEmpty() && mnc.isNotEmpty()) {
                        // Store both formats: "MCCMNC" and padded MNC if needed
                        val key = "$mcc$mnc"
                        if (brand.isNotEmpty()) {
                            mccMncMap[key] = brand
                        }
                    }
                }
            }
            
            reader.close()
            isLoaded = true
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
    
    /**
     * Look up operator brand by MCC+MNC
     * @param mccMnc Combined MCC+MNC string (e.g., "46692" for Chunghwa Taiwan)
     * @return Brand name or null if not found
     */
    fun getBrand(mccMnc: String): String? {
        if (!isLoaded) return null
        
        // Try direct lookup
        mccMncMap[mccMnc]?.let { return it }
        
        // Try with MNC padding (2-digit vs 3-digit MNC)
        if (mccMnc.length >= 5) {
            val mcc = mccMnc.substring(0, 3)
            val mnc = mccMnc.substring(3)
            
            // Try 2-digit MNC (e.g., "01" -> "1")
            if (mnc.length == 2 && mnc.startsWith("0")) {
                mccMncMap["$mcc${mnc.substring(1)}"]?.let { return it }
            }
            
            // Try 3-digit MNC with leading zero
            if (mnc.length == 2) {
                mccMncMap["${mcc}0$mnc"]?.let { return it }
            }
        }
        
        return null
    }
}
