#pragma once

#include "Config.h"

class ConfigManager {
public:
    explicit ConfigManager(const std::string& config_file = "");
    
    // Configuration loading and saving
    bool load();
    bool save() const;
    bool saveAs(const std::string& filename);
    
    // Configuration access
    const Config& getConfig() const;
    void setConfig(const Config& config);
    
    // Individual setting updates
    void updateNetworkConfig(const NetworkConfig& network_config);
    void updatePuzzleConfig(const PuzzleConfig& puzzle_config);
    void updateGPUConfig(const GPUConfig& gpu_config);
    void updateResourceConfig(const ResourceConfig& resource_config);
    void updateLoggingConfig(const LoggingConfig& logging_config);
    void updateUIConfig(const UIConfig& ui_config);
    
    // Validation
    bool validateConfig() const;
    std::vector<std::string> getValidationErrors() const;
    
    // File path management
    std::string getConfigFilePath() const { return config_file_path_; }
    std::string getDefaultConfigPath() const;
    std::string getDataDirectory() const;

    // True when the last load() found an existing config file it could not
    // parse. save() then refuses to overwrite that file so a typo does not
    // silently replace the user's settings with defaults.
    bool lastLoadFailedToParse() const { return parse_failed_path_ == config_file_path_ && !parse_failed_path_.empty(); }
    // True when the last load() found config.json empty or unparsable and
    // replaced it with a parsable <config>.bak (the broken file is kept as
    // <config>.broken.<suffix>).
    bool lastLoadRestoredFromBackup() const { return restored_from_backup_; }
    
private:
    Config config_;
    std::string config_file_path_;
    std::string parse_failed_path_;
    bool restored_from_backup_ = false;
    
    // JSON serialization helpers
    void toJson(const Config& config, std::string& json) const;
    bool fromJson(const std::string& json, Config& config) const;
    
    // Platform-specific path helpers
    std::string getPlatformConfigPath() const;
    std::string getPlatformDataPath() const;
    
    // Validation helpers
    bool validateNetworkConfig(const NetworkConfig& config, std::vector<std::string>& errors) const;
    bool validatePuzzleConfig(const PuzzleConfig& config, std::vector<std::string>& errors) const;
    bool validateGPUConfig(const GPUConfig& config, std::vector<std::string>& errors) const;
    bool validateResourceConfig(const ResourceConfig& config, std::vector<std::string>& errors) const;

    std::string generateUuidV4() const;
};