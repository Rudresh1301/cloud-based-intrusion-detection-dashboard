import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  CloudUpload,
  FileText,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Search,
  ArrowRight,
  Database,
  Cloud
} from 'lucide-react';
import { validateLogs, uploadAndAnalyzeLogs } from '../services/api';

export const UploadLogs = () => {
  const navigate = useNavigate();

  const [file, setFile] = useState(null);
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      selectAndValidateFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      selectAndValidateFile(e.target.files[0]);
    }
  };

  const selectAndValidateFile = async (selectedFile) => {
    setFile(selectedFile);
    setErrorMsg('');
    setAnalysisResult(null);
    setIsValidating(true);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const res = await validateLogs(formData);
      setValidationResult(res.data.validation);
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Failed to parse file schema.');
      setValidationResult(null);
    } finally {
      setIsValidating(false);
    }
  };

  const handleAnalyzeLogs = async () => {
    if (!file) return;
    setIsProcessing(true);
    setErrorMsg('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await uploadAndAnalyzeLogs(formData);
      setAnalysisResult(res.data);
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Analysis processing failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn max-w-6xl mx-auto">
      {/* Page Title & Intro */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1E2D4A]">
        <div>
          <h2 className="text-xl font-bold text-[#F1F5F9]">Upload & Ingest Security Logs</h2>
          <p className="text-xs text-[#94A3B8] mt-1">
            Ingest structured server, firewall, or application access logs for cloud storage and threat detection.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-medium text-[#00C8FF] bg-[#121E32] px-3 py-1.5 rounded-xl border border-[#1E2D4A]">
          <Cloud size={14} /> Cloud Object Storage Pipeline Active
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-[#FF4560]/20 border border-[#FF4560]/50 text-[#FF4560] text-xs font-semibold flex items-center gap-2">
          <AlertTriangle size={16} /> {errorMsg}
        </div>
      )}

      {/* Drag & Drop Upload Zone */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`relative flex flex-col items-center justify-center p-8 rounded-2xl border-2 border-dashed transition-all cursor-pointer ${
          dragActive
            ? 'border-[#00C8FF] bg-[#00C8FF]/10 shadow-neon-cyan'
            : 'border-[#1E2D4A] bg-[#121E32]/70 hover:border-[#087FE5]/60 hover:bg-[#121E32]'
        }`}
      >
        <input
          type="file"
          id="file-upload"
          accept=".csv,.txt"
          onChange={handleFileChange}
          className="absolute inset-0 opacity-0 cursor-pointer"
        />

        <div className="p-4 rounded-2xl bg-[#087FE5]/20 border border-[#087FE5]/40 text-[#00C8FF] mb-3 shadow-neon-blue">
          <CloudUpload size={32} />
        </div>

        <h4 className="text-sm font-bold text-[#F1F5F9] text-center">
          {file ? file.name : 'Drag & Drop Security Log File or Browse'}
        </h4>
        <p className="text-xs text-[#94A3B8] mt-1 text-center">
          Supported formats: <span className="text-[#00C8FF] font-semibold">.CSV</span> or space-delimited <span className="text-[#00C8FF] font-semibold">.TXT</span> (Max 50MB)
        </p>

        {file && (
          <span className="mt-3 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-[#080D19] text-[#00D68F] border border-[#00D68F]/40">
            {(file.size / 1024).toFixed(1)} KB Selected
          </span>
        )}
      </div>

      {/* Schema Requirement Guide */}
      <div className="p-4 rounded-xl bg-[#0D1526] border border-[#1E2D4A] text-xs text-[#94A3B8] flex flex-wrap items-center justify-between gap-3">
        <span className="font-semibold text-[#F1F5F9]">Expected Canonical Columns:</span>
        <div className="flex flex-wrap gap-2 font-mono text-[11px]">
          {['timestamp', 'source_ip', 'username', 'event_type', 'status', 'endpoint'].map((col) => (
            <span key={col} className="px-2 py-0.5 rounded bg-[#121E32] border border-[#1E2D4A] text-[#00C8FF]">
              {col}
            </span>
          ))}
        </div>
      </div>

      {/* Validation Results Card */}
      {isValidating && (
        <div className="flex items-center justify-center p-8 bg-[#121E32] rounded-2xl border border-[#1E2D4A]">
          <RefreshCw className="w-6 h-6 text-[#00C8FF] animate-spin mr-3" />
          <span className="text-xs font-semibold text-[#94A3B8]">Validating schema and data integrity...</span>
        </div>
      )}

      {validationResult && (
        <div className="p-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1E2D4A]">
            <div className="flex items-center gap-2.5">
              {validationResult.valid ? (
                <div className="p-2 rounded-xl bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40">
                  <CheckCircle2 size={18} />
                </div>
              ) : (
                <div className="p-2 rounded-xl bg-[#FF4560]/20 text-[#FF4560] border border-[#FF4560]/40">
                  <AlertTriangle size={18} />
                </div>
              )}
              <div>
                <h4 className="text-sm font-bold text-[#F1F5F9]">
                  {validationResult.valid ? 'File Validation Passed' : 'Validation Errors Identified'}
                </h4>
                <p className="text-xs text-[#94A3B8]">
                  {validationResult.valid
                    ? 'Schema matches required fields. Ready for threat detection analysis.'
                    : 'File cannot be analyzed until schema issues are corrected.'}
                </p>
              </div>
            </div>

            {validationResult.valid && !analysisResult && (
              <button
                onClick={handleAnalyzeLogs}
                disabled={isProcessing}
                className="py-2.5 px-6 rounded-xl bg-gradient-to-r from-[#087FE5] to-[#00A8FF] text-white font-bold text-xs shadow-neon-blue hover:brightness-110 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {isProcessing ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" /> Analyzing Logs...
                  </>
                ) : (
                  <>
                    <Search size={14} /> Analyze Logs Now
                  </>
                )}
              </button>
            )}
          </div>

          {/* Validation Stats Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-xl bg-[#080D19] border border-[#1E2D4A]">
              <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Total Records</span>
              <p className="text-lg font-bold text-[#F1F5F9] mt-0.5">{validationResult.stats.total_rows}</p>
            </div>
            <div className="p-3 rounded-xl bg-[#080D19] border border-[#1E2D4A]">
              <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Valid Rows</span>
              <p className="text-lg font-bold text-[#00D68F] mt-0.5">{validationResult.stats.valid_rows}</p>
            </div>
            <div className="p-3 rounded-xl bg-[#080D19] border border-[#1E2D4A]">
              <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Duplicates Detected</span>
              <p className="text-lg font-bold text-[#FFB020] mt-0.5">{validationResult.stats.duplicate_rows}</p>
            </div>
            <div className="p-3 rounded-xl bg-[#080D19] border border-[#1E2D4A]">
              <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Invalid IP Syntax</span>
              <p className="text-lg font-bold text-[#FF4560] mt-0.5">{validationResult.stats.invalid_rows}</p>
            </div>
          </div>

          {/* Preview Table */}
          {validationResult.preview && validationResult.preview.length > 0 && (
            <div>
              <span className="text-xs font-bold text-[#F1F5F9] block mb-2">Ingestion Preview Sample (First 5 Rows)</span>
              <div className="overflow-x-auto rounded-xl border border-[#1E2D4A]">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#080D19] text-[#94A3B8] text-[11px]">
                    <tr>
                      {validationResult.stats.detected_columns.map((c) => (
                        <th key={c} className="p-2.5 font-semibold">{c}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1E2D4A]/60">
                    {validationResult.preview.slice(0, 5).map((row, i) => (
                      <tr key={i} className="hover:bg-[#16253e]">
                        {validationResult.stats.detected_columns.map((c) => (
                          <td key={c} className="p-2.5 font-mono text-[11px] text-[#F1F5F9] max-w-xs truncate">
                            {String(row[c] || '')}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Analysis Result Banner */}
      {analysisResult && (
        <div className="p-6 rounded-2xl bg-[#0D1526] border border-[#00D68F]/40 shadow-neon-green space-y-4 animate-fadeIn">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40">
                <CheckCircle2 size={24} />
              </div>
              <div>
                <h3 className="text-base font-bold text-[#F1F5F9]">
                  Log Analysis & Detection Completed
                </h3>
                <p className="text-xs text-[#94A3B8] mt-0.5">
                  Stored in {analysisResult.storage?.storage_type}. {analysisResult.threats_found} threat incident(s) flagged across {analysisResult.suspicious_ips_count} source IPs.
                </p>
              </div>
            </div>

            <button
              onClick={() => navigate('/')}
              className="py-2.5 px-5 rounded-xl bg-gradient-to-r from-[#087FE5] to-[#00A8FF] text-white font-bold text-xs shadow-neon-blue hover:brightness-110 transition-all flex items-center gap-2 cursor-pointer"
            >
              Go to Dashboard <ArrowRight size={14} />
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-xl bg-[#121E32] border border-[#1E2D4A]">
              <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Total Ingested</span>
              <p className="text-lg font-bold text-[#F1F5F9] mt-0.5">{analysisResult.total_records} events</p>
            </div>
            <div className="p-3 rounded-xl bg-[#121E32] border border-[#1E2D4A]">
              <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Rule Heuristic Alerts</span>
              <p className="text-lg font-bold text-[#FF4560] mt-0.5">{analysisResult.rule_alerts_count}</p>
            </div>
            <div className="p-3 rounded-xl bg-[#121E32] border border-[#1E2D4A]">
              <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">ML Behavioral Anomalies</span>
              <p className="text-lg font-bold text-[#00C8FF] mt-0.5">{analysisResult.ml_alerts_count}</p>
            </div>
            <div className="p-3 rounded-xl bg-[#121E32] border border-[#1E2D4A]">
              <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Risk Level</span>
              <p className="text-lg font-bold text-[#FF4560] mt-0.5">{analysisResult.overall_risk?.level || 'HIGH'}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
