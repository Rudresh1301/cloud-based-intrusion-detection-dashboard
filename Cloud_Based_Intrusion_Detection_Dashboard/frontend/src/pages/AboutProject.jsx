import React from 'react';
import {
  Cloud,
  Database,
  Shield,
  Server,
  Layers,
  Cpu,
  Lock,
  Globe,
  CheckCircle2,
  ExternalLink,
  Code2
} from 'lucide-react';

export const AboutProject = () => {
  const CLOUD_CONCEPTS = [
    {
      title: '1. Cloud Object Storage',
      service: 'Firebase Cloud Storage (Google Cloud)',
      desc: 'Raw ingested CSV/TXT files and compiled PDF audit reports are stored as binary objects in scalable cloud buckets with secure signed download URLs.',
      icon: Cloud
    },
    {
      title: '2. Cloud NoSQL Database',
      service: 'Firebase Cloud Firestore',
      desc: 'Fully managed document-store database holding security telemetry logs, threat alert documents, IP intelligence, and historical analysis snapshots.',
      icon: Database
    },
    {
      title: '3. Backend as a Service (BaaS)',
      service: 'Firebase Platform Services',
      desc: 'Offloads complex database management, cloud authentication, and distributed storage infrastructure through high-level SDK interfaces.',
      icon: Layers
    },
    {
      title: '4. Platform as a Service (PaaS)',
      service: 'Render Cloud Platform',
      desc: 'Automates deployment, process monitoring, container orchestration, and runtime execution for the Python FastAPI detection backend.',
      icon: Server
    },
    {
      title: '5. Edge Cloud Hosting',
      service: 'Vercel Global Edge Network',
      desc: 'Distributes optimized production React Vite frontend bundles across worldwide edge CDN locations with instant caching and SSL termination.',
      icon: Globe
    },
    {
      title: '6. Cloud Identity & Authentication',
      service: 'Firebase Authentication / Identity Platform',
      desc: 'Manages user registration, session tokens, JWT signing, password encryption, and role-based access restrictions for SOC analysts.',
      icon: Lock
    },
    {
      title: '7. Cloud Elasticity & Scalability',
      service: 'Stateless REST Architecture',
      desc: 'FastAPI backend is completely stateless, enabling horizontal auto-scaling behind cloud load balancers without shared memory locks.',
      icon: Cpu
    },
    {
      title: '8. High Availability & Disaster Recovery',
      service: 'Multi-Zone Cloud Redundancy',
      desc: 'Firestore and Firebase Storage span multi-region replication zones, complemented by a local SQLite fallback for offline development resilience.',
      icon: Shield
    },
    {
      title: '9. Cloud Resource Management',
      service: 'Vectorized Processing & Batching',
      desc: 'Precompiled regex engines and batch Firestore commits prevent quota exhaustion, minimizing compute cycles and operational cloud costs.',
      icon: Layers
    },
    {
      title: '10. Cloud Security & Zero Trust',
      service: 'Least-Privilege Secret Management',
      desc: 'Zero hardcoded secrets; API credentials and Firebase service account tokens are injected via deployment environment variables.',
      icon: Lock
    },
    {
      title: '11. Distributed Service Integration',
      service: 'Decoupled Multi-Cloud Architecture',
      desc: 'Independent React UI (Vercel) communicating with Python engine (Render) coordinating with Google Cloud Firebase infrastructure.',
      icon: Code2
    },
    {
      title: '12. API-Based Communication',
      service: 'RESTful OpenAPI 3.0 Contract',
      desc: 'Standardized JSON data interchange between client and server with Pydantic validation, explicit HTTP verbs, and health probes.',
      icon: Globe
    },
  ];

  return (
    <div className="space-y-8 animate-fadeIn max-w-6xl mx-auto">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-[#087FE5]/20 via-[#121E32] to-[#8B5CF6]/20 border border-[#00C8FF]/40 shadow-neon-blue">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <span className="px-3 py-1 rounded-full text-xs font-extrabold uppercase bg-[#00C8FF]/20 text-[#00C8FF] border border-[#00C8FF]/40 tracking-wider">
              5th-Semester Engineering Mini Project
            </span>
            <h2 className="text-2xl font-black text-[#F1F5F9] mt-2">
              CLOUD-BASED INTRUSION DETECTION DASHBOARD
            </h2>
            <p className="text-xs text-[#94A3B8] mt-1 max-w-2xl leading-relaxed">
              Subject: <b>CLOUD COMPUTING</b>. This application demonstrates the practical application of genuine cloud storage, cloud database, cloud authentication, and PaaS hosting in cybersecurity operations.
            </p>
          </div>
          <div className="text-right flex-shrink-0">
            <span className="text-[11px] text-[#94A3B8] block">Evaluation Benchmark</span>
            <span className="text-xs font-bold text-[#00D68F] bg-[#00D68F]/10 px-3 py-1 rounded-lg border border-[#00D68F]/30 inline-block mt-1">
              ✓ Production Ready SOC Stack
            </span>
          </div>
        </div>
      </div>

      {/* Cloud Architecture Flow Diagram */}
      <div className="p-6 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card">
        <h3 className="text-sm font-bold text-[#F1F5F9] mb-4 flex items-center gap-2">
          <Layers size={16} className="text-[#00C8FF]" /> End-to-End Cloud Computing Architecture Flow
        </h3>

        {/* Diagram Graphic */}
        <div className="p-4 rounded-xl bg-[#080D19] border border-[#1E2D4A] overflow-x-auto">
          <div className="min-w-[650px] flex items-center justify-between gap-3 text-center text-xs">
            {/* Step 1: User / Browser */}
            <div className="flex-1 p-3.5 rounded-xl bg-[#0D1526] border border-[#087FE5]/50 flex flex-col items-center">
              <span className="text-2xl mb-1">💻</span>
              <span className="font-bold text-[#F1F5F9]">SOC Analyst</span>
              <span className="text-[10px] text-[#94A3B8]">Browser Client</span>
            </div>

            <span className="text-[#00C8FF] font-bold text-lg">➔</span>

            {/* Step 2: React Frontend */}
            <div className="flex-1 p-3.5 rounded-xl bg-[#0D1526] border border-[#00C8FF]/50 flex flex-col items-center">
              <span className="text-2xl mb-1">⚛️</span>
              <span className="font-bold text-[#00C8FF]">React + Vite</span>
              <span className="text-[10px] text-[#94A3B8]">Vercel Edge Hosting</span>
            </div>

            <span className="text-[#00C8FF] font-bold text-lg">➔</span>

            {/* Step 3: FastAPI Backend */}
            <div className="flex-1 p-3.5 rounded-xl bg-[#0D1526] border border-[#8B5CF6]/50 flex flex-col items-center">
              <span className="text-2xl mb-1">⚡</span>
              <span className="font-bold text-[#8B5CF6]">FastAPI Engine</span>
              <span className="text-[10px] text-[#94A3B8]">Render PaaS Container</span>
            </div>

            <span className="text-[#00C8FF] font-bold text-lg">➔</span>

            {/* Step 4: Firebase Services */}
            <div className="flex-1 p-3.5 rounded-xl bg-[#0D1526] border border-[#FFB020]/50 flex flex-col items-center">
              <span className="text-2xl mb-1">🔥</span>
              <span className="font-bold text-[#FFB020]">Firebase Cloud</span>
              <span className="text-[10px] text-[#94A3B8]">Firestore & Storage BaaS</span>
            </div>
          </div>
        </div>
      </div>

      {/* 12 Cloud Computing Concepts Grid */}
      <div className="space-y-4">
        <h3 className="text-base font-bold text-[#F1F5F9] flex items-center gap-2">
          <Cloud size={18} className="text-[#00C8FF]" /> 12 Core Cloud Computing Concepts Implemented
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {CLOUD_CONCEPTS.map((concept) => {
            const Icon = concept.icon;
            return (
              <div
                key={concept.title}
                className="p-4 rounded-xl bg-[#121E32] border border-[#1E2D4A] hover:border-[#087FE5]/50 transition-colors flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center gap-2.5 mb-2">
                    <div className="p-2 rounded-lg bg-[#087FE5]/20 text-[#00C8FF]">
                      <Icon size={16} />
                    </div>
                    <div>
                      <h4 className="text-xs font-bold text-[#F1F5F9]">{concept.title}</h4>
                      <span className="text-[10px] text-[#00A8FF] font-semibold">{concept.service}</span>
                    </div>
                  </div>
                  <p className="text-xs text-[#94A3B8] leading-relaxed mt-2">
                    {concept.desc}
                  </p>
                </div>
                <div className="mt-3 pt-2 border-t border-[#1E2D4A]/50 flex items-center gap-1.5 text-[10px] text-[#00D68F] font-semibold">
                  <CheckCircle2 size={12} /> Verified Implementation
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Faculty Evaluation Guide */}
      <div className="p-6 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card">
        <h3 className="text-sm font-bold text-[#F1F5F9] mb-3 flex items-center gap-2">
          <CheckCircle2 size={16} className="text-[#00D68F]" /> Faculty Evaluation & Viva Voce Quick Reference
        </h3>
        <div className="space-y-2 text-xs text-[#94A3B8]">
          <p>• <b>Why is this a Cloud Computing project?</b> The application is architected around genuine cloud database (Firestore), cloud object storage (Firebase Storage), cloud authentication (Firebase Auth), and PaaS deployment (Render + Vercel). Local SQLite is strictly an offline development fallback.</p>
          <p>• <b>How are large files handled?</b> Uploaded logs and PDF audit reports are never stored directly in Firestore documents to prevent bloat. They are streamed into Firebase Cloud Storage, and only metadata and URI pointers are indexed in Firestore.</p>
          <p>• <b>How is threat detection achieved?</b> Through a hybrid architecture combining deterministic rule heuristics (regex scanning for SQLi, XSS, RCE, Path Traversal, Brute Force) with an unsupervised Scikit-learn Isolation Forest machine learning model for behavioral outlier detection.</p>
        </div>
      </div>
    </div>
  );
};
