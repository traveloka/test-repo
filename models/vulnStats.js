var mongoose = require('mongoose');

// vuln_stats schema
var vulnStats = mongoose.Schema({
    projectName: {
        type: String,
        unique: true,
        required: true,
        trim: true
    },
    affectedFiles: {
        type: Number,
        required: true,
        default: 0
    },
    totalVuln: {
        type: Number,
        required: true,
        default: 0
    },
    low: {
        type: Number,
        required: true,
        default: 0
    },
    med: {
        type: Number,
        required: true,
        default: 0
    },
    high: {
        type: Number,
        required: true,
        default: 0
    },
    critical: {
        type: Number,
        required: true,
        default: 0
    },
    lastScan: {
        type: Number,
        required: true,
        default: 0
    }
});

let Vulnstat = module.exports = mongoose.model('VulnStats', vulnStats);