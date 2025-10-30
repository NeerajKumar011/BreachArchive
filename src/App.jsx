import React, { useState, useMemo, useEffect } from 'react';
import { 
  User, 
  Activity,
  Database,
  Home,
  FileCode,
  Contact,
  Calendar,
  MapPin,
  Users,
  Shield,
  Eye,
  Terminal,
  Brain,
  TrendingUp,
  AlertTriangle,
  Zap,
  Book,
  Search,
  Lock,
  UploadCloud,
  LogIn,
  LogOut,
  Edit, 
  Trash2 
} from 'lucide-react';

// --- Toast Notifications ---
import toast, { Toaster } from 'react-hot-toast';

// --- Recharts Imports ---
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  Legend,
  LineChart, 
  Line,      
  CartesianGrid, 
  Tooltip,       
  XAxis,         
  YAxis       
} from 'recharts';

// --- Firebase Imports ---
import { initializeApp } from 'firebase/app';
import { 
  getAuth, 
  onAuthStateChanged, 
  signInAnonymously, 
  signInWithEmailAndPassword,
  signOut
} from 'firebase/auth';

import { 
  getFirestore, 
  doc, 
  getDocs, 
  setDoc, 
  onSnapshot, 
  collection, 
  query, 
  addDoc,
  updateDoc, 
  deleteDoc, 
  limit,
  setLogLevel
} from 'firebase/firestore';

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// +++ DYNAMIC FIREBASE CONFIGURATION (Uses import.meta.env.VITE_*) +++
// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
const firebaseConfig = {
  // CORRECT VITE SYNTAX: Reads from Vercel's or local .env.local VITE_ environment variables
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID
};
// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// +++ ADMIN EMAIL (Reads from VITE_ Environment Variable) +++
// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
const ADMIN_EMAIL = import.meta.env.VITE_ADMIN_EMAIL;
// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


/* --- Main Application Component --- */
export default function App() {
  
  /* --- State Variables --- */
  
  // App Navigation
  const [activeView, setActiveView] = useState('home'); 
  
  // Incident Data
  const [selectedIncident, setSelectedIncident] = useState(null); 
  
  // Incident Search & Filter
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    dateRange: 'all',
    attackType: 'all',
    industry: 'all',
    severity: 'all'
  });
  
  // Pagination
  const [visibleIncidentCount, setVisibleIncidentCount] = useState(9); 

  // --- Firebase & Data State ---
  const [app, setApp] = useState(null);
  const [auth, setAuth] = useState(null);
  const [db, setDb] = useState(null);
  const [userId, setUserId] = useState(null);
  const [userEmail, setUserEmail] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [isAuthReady, setIsAuthReady] = useState(false); 
  const [allIncidents, setAllIncidents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  // --- State for Edit/Delete ---
  const [incidentToEdit, setIncidentToEdit] = useState(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [incidentToDelete, setIncidentToDelete] = useState(null);

  
  /* --- Event Handlers --- */
  
  // Handles navigation.
  const handleNavClick = (view) => {
    setActiveView(view);
    setSelectedIncident(null);
    if (view !== 'search') {
      setSearchTerm('');
    }
    // If we're navigating away from the admin page, clear any pending edit
    if (view !== 'admin') {
      setIncidentToEdit(null);
    }
    setVisibleIncidentCount(9);
  };
  
  // Handles clicking the "Show More" button
  const handleShowMore = () => {
    setVisibleIncidentCount(prevCount => prevCount + 9); 
  };

  // Handle Admin Logout
  const handleLogout = async () => {
    if (!auth) return;
    try {
      await signOut(auth);
      setIncidentToEdit(null); // Clear edit state on logout
      handleNavClick('home'); 
      toast.success("Logged out successfully."); 
    } catch (error) {
      console.error("Error signing out: ", error);
      toast.error("Error signing out."); 
    }
  };

  // --- Edit & Delete Handlers ---

  // Called when Admin clicks "Edit" on an incident
  const handleEditRequest = (incident) => {
    setIncidentToEdit(incident);
    handleNavClick('admin'); // Go to the admin page
  };

  // Called when Admin clicks "Delete" on an incident
  const handleDeleteRequest = (incident) => {
    setIncidentToDelete(incident);
    setShowDeleteModal(true); // Open the confirmation modal
  };

  // Called from the Admin form when "Cancel Edit" is clicked
  const handleCancelEdit = () => {
    setIncidentToEdit(null);
    handleNavClick('search'); // Go back to the incident list
  };

  // Called when a new incident is SUBMITTED
  const handleIncidentSubmitted = () => {
    handleNavClick('search'); // Go to incident list
  };

  // Called when an existing incident is UPDATED
  const handleIncidentUpdated = () => {
    setIncidentToEdit(null); // Clear the edit state
    handleNavClick('search'); // Go to incident list
  };

  // Called when "Cancel" is clicked on the delete modal
  const handleDeleteCancel = () => {
    setShowDeleteModal(false);
    setIncidentToDelete(null);
  };

  // Called when "Confirm Delete" is clicked on the modal
  const handleDeleteConfirm = async () => {
    if (!incidentToDelete || !db || !isAdmin) return;
    
    setIsLoading(true);
    try {
      // Get the document ID from the incident object
      const docId = incidentToDelete.docId;
      if (!docId) {
        throw new Error("Incident has no Document ID!");
      }
      
      const incidentRef = doc(db, "incidents", docId);
      await deleteDoc(incidentRef);
      
      console.log("Incident deleted successfully!");
      toast.success("Incident deleted successfully!"); 
      handleDeleteCancel();      // Close the modal
      handleNavClick('search'); // Go to the incident list
    } catch (error) {
      console.error("Error deleting document: ", error);
      toast.error("Error deleting incident."); 
    }
    setIsLoading(false);
  };

  /* --- Auth Initialization Effect (on mount) --- */
  useEffect(() => {
    // Basic check for missing API key
    if (!firebaseConfig.apiKey) {
      console.error("Firebase API Key is missing! Check your Vercel/local environment variables.");
      setIsAuthReady(true); // Stop loading/auth attempts
      return;
    }
    
    const firebaseApp = initializeApp(firebaseConfig);
    const firebaseAuth = getAuth(firebaseApp);
    const firestoreDb = getFirestore(firebaseApp);
    
    setLogLevel('Debug');
    setApp(firebaseApp);
    setAuth(firebaseAuth);
    setDb(firestoreDb);
    
    const unsubscribe = onAuthStateChanged(firebaseAuth, async (user) => {
      if (user) {
        setUserId(user.uid);
        if (user.email === ADMIN_EMAIL) {
          console.log("User signed in as ADMIN:", user.email);
          setIsAdmin(true);
          setUserEmail(user.email);
        } else {
          console.log("User signed in as GUEST (Anonymous):", user.uid);
          setIsAdmin(false);
          setUserEmail(null);
        }
        setIsAuthReady(true); 
      } else {
        console.log("No user. Attempting to sign in anonymously...");
        setIsAdmin(false);
        setUserEmail(null);
        try {
          await signInAnonymously(firebaseAuth);
        } catch (error) {
          console.error("Error signing in anonymously: ", error);
          setIsAuthReady(true); 
        }
      }
    });
    
    return () => unsubscribe();
      
  }, []); 

  
  /* --- Database Seeding Effect --- */
  useEffect(() => {
    // Only seed if DB is ready AND user is an admin
    if (!db || !isAuthReady || !isAdmin) return;

    const incidentsRef = collection(db, "incidents");

    const seedDatabase = async () => {
      try {
        const q = query(incidentsRef, limit(1));
        const snapshot = await getDocs(q);
        
        if (snapshot.empty) {
          console.log("Database is empty. Seeding featured incidents...");
          const baseIncidents = [
            { id: 1, name: "SolarWinds Supply Chain Attack", date: "2020-12-13", location: "Global", victims: ["SolarWinds", "US Government Agencies", "Fortune 500 Companies"], attackers: "APT29 (Cozy Bear/SVR)", attackVector: "Supply Chain Compromise", malware: "SUNBURST, TEARDROP", vulnerabilities: ["Supply Chain Trust", "Code Signing Certificate Abuse"], tactics: ["Initial Access", "Persistence", "Defense Evasion", "Command and Control"], detectionMethod: "FireEye internal security team discovery", responseActions: ["Emergency patching", "Network segmentation", "Threat hunting"], lawEnforcement: "FBI, CISA joint investigation", outcome: "Ongoing remediation, attribution to Russian SVR", impact: "High - 18,000+ organizations affected", industry: "Government", severity: "Critical", references: ["CISA Alert AA20-352A", "FireEye Blog", "NSA Advisory"], technicalSummary: "Advanced persistent threat group compromised SolarWinds Orion software updates, inserting SUNBURST backdoor that provided covert access to victim networks for months.", nonTechnicalSummary: "Hackers secretly modified a popular network monitoring software that thousands of organizations use, giving them access to sensitive government and corporate systems.", lessonsLearned: [ "Implement rigorous supply chain security controls", "Deploy advanced behavioral analytics for anomaly detection", "Establish zero-trust architecture principles", "Enhance code signing and software integrity verification" ], opsecFailures: [ "Reused infrastructure across multiple operations", "Left forensic artifacts in victim environments", "Used predictable naming conventions for some tools" ], defensiveGaps: [ "Insufficient supply chain vetting", "Limited network segmentation", "Inadequate behavioral monitoring" ], featured: true },
            { id: 2, name: "Equifax Data Breach", date: "2017-07-29", location: "United States", victims: ["Equifax", "147 million consumers"], attackers: "Chinese PLA Unit 54777 (indicted)", attackVector: "Web Application Exploitation", malware: "Web shells, custom tools", vulnerabilities: ["CVE-2017-5638 (Apache Struts)"], tactics: ["Initial Access", "Persistence", "Credential Access", "Collection", "Exfiltration"], detectionMethod: "Internal security monitoring (delayed)", responseActions: ["System isolation", "Forensic investigation", "Consumer notification"], lawEnforcement: "FBI investigation, DOJ indictments", outcome: "4 Chinese military officers indicted, $700M+ in fines", impact: "Critical - Personal data of 147M individuals", industry: "Financial Services", severity: "Critical", references: ["DOJ Indictment", "House Committee Report", "GAO Report"], technicalSummary: "Attackers exploited unpatched Apache Struts vulnerability (CVE-2017-5638) to gain initial access, then moved laterally through network to access sensitive consumer databases.", nonTechnicalSummary: "Hackers used a known security flaw in web software that wasn't updated, allowing them to steal personal information of nearly half of all Americans.", lessonsLearned: [ "Implement comprehensive patch management programs", "Deploy web application firewalls and input validation", "Establish real-time security monitoring", "Conduct regular penetration testing" ], opsecFailures: [ "Used compromised systems for extended periods without clearing logs", "Left behind forensic evidence of lateral movement", "Failed to completely cover tracks during exfiltration" ], defensiveGaps: [ "Critical patch not applied despite availability", "Insufficient network segmentation", "Delayed breach detection (76 days)" ], featured: true },
            { id: 3, name: "WannaCry Ransomware", date: "2017-05-12", location: "Global", victims: ["NHS UK", "FedEx", "Telefonica", "300,000+ computers worldwide"], attackers: "Lazarus Group (North Korea)", attackVector: "Ransomware", malware: "WannaCry ransomware", vulnerabilities: ["MS17-010 EternalBlue SMB exploit"], tactics: ["Initial Access", "Lateral Movement", "Impact"], detectionMethod: "Global outbreak detection by security researchers", responseActions: ["Emergency patching", "Network isolation", "Kill switch activation"], lawEnforcement: "US, UK attribution to North Korea", outcome: "Stopped by kill switch discovery, ongoing attribution", impact: "Critical - Global infrastructure disruption", industry: "Healthcare", severity: "Critical", references: ["NCSC Analysis", "US-CERT Alert", "Europol Report"], technicalSummary: "Self-propagating ransomware exploiting Windows SMB vulnerability leaked from NSA tools, spreading rapidly across unpatched systems globally.", nonTechnicalSummary: "A computer virus that locked files and demanded payment spread automatically across the internet, affecting hospitals, businesses, and government agencies worldwide.", lessonsLearned: [ "Maintain current patching across all systems", "Implement network segmentation to limit worm spread", "Deploy endpoint detection and response solutions", "Establish incident response procedures for rapid containment" ], opsecFailures: [ "Hardcoded kill switch domain enabled takedown", "Reused Bitcoin wallets traceable to previous operations", "Left attribution artifacts linking to previous Lazarus campaigns" ], defensiveGaps: [ "Widespread failure to apply critical security patches", "Insufficient network segmentation", "Inadequate backup and recovery procedures" ], featured: true },
            { id: 4, name: "Colonial Pipeline Ransomware", date: "2021-05-07", location: "United States", victims: ["Colonial Pipeline", "US East Coast fuel supply"], attackers: "DarkSide Ransomware Group", attackVector: "Ransomware", malware: "DarkSide ransomware", vulnerabilities: ["Compromised VPN credentials"], tactics: ["Initial Access", "Lateral Movement", "Data Encryption", "Extortion"], detectionMethod: "Internal IT systems monitoring", responseActions: ["Pipeline shutdown", "FBI involvement", "Ransom payment"], lawEnforcement: "FBI investigation, partial ransom recovery", outcome: "Pipeline restored, $2.3M ransom partially recovered", impact: "Critical - US fuel supply disruption", industry: "Energy", severity: "Critical", references: ["FBI Statement", "CISA Advisory", "Colonial Pipeline Report"], technicalSummary: "DarkSide ransomware group gained access through compromised VPN credentials, deployed ransomware across operational technology networks forcing pipeline shutdown.", nonTechnicalSummary: "Cybercriminals locked down the computer systems controlling a major fuel pipeline, causing gas shortages across the Eastern United States.", lessonsLearned: [ "Secure remote access with multi-factor authentication", "Segregate operational technology from IT networks", "Implement comprehensive backup and recovery procedures", "Develop incident response plans for critical infrastructure" ], opsecFailures: [ "Used known ransomware signature patterns", "Left behind recovery keys in some encrypted systems", "Reused infrastructure from previous campaigns" ], defensiveGaps: [ "Inadequate VPN security controls", "Insufficient network segmentation", "Limited OT/IT security monitoring" ], featured: true },
            { id: 5, name: "NotPetya Cyberattack", date: "2017-06-27", location: "Global (Ukraine focus)", victims: ["Ukrainian government", "Maersk", "FedEx", "Pharmaceutical companies"], attackers: "Sandworm (Russian GRU)", attackVector: "Supply Chain Compromise", malware: "NotPetya wiper malware", vulnerabilities: ["Ukrainian tax software compromise", "EternalBlue exploit"], tactics: ["Initial Access", "Lateral Movement", "Defense Evasion", "Impact"], detectionMethod: "Global security community analysis", responseActions: ["System isolation", "Data recovery efforts", "Attribution investigation"], lawEnforcement: "US, UK attribution to Russian military", outcome: "Attributed to Russian state actors, $10B+ global damages", impact: "Critical - $10+ billion in global damages", industry: "Government", severity: "Critical", references: ["US Attribution Statement", "Maersk Impact Report", "NCSC Analysis"], technicalSummary: "State-sponsored wiper malware disguised as ransomware, initially spread through compromised Ukrainian tax software, then globally via EternalBlue exploit.", nonTechnicalSummary: "What appeared to be ransomware was actually a destructive cyberweapon that permanently destroyed data, initially targeting Ukraine but spreading worldwide.", lessonsLearned: [ "Implement robust supply chain security for software updates", "Deploy network segmentation to limit lateral movement", "Maintain offline backups for critical data recovery", "Develop geopolitical threat awareness programs" ], opsecFailures: [ "Left attribution artifacts linking to previous GRU operations", "Used predictable infrastructure patterns", "Reused malware code signatures from previous campaigns" ], defensiveGaps: [ "Trusted software update mechanisms compromised", "Insufficient network isolation", "Limited nation-state threat detection capabilities" ], featured: true },
            { id: 6, name: "Target Data Breach", date: "2013-11-27", location: "United States", victims: ["Target Corporation", "40 million credit card records", "70 million customer records"], attackers: "Financially motivated cybercriminals", attackVector: "Third-party vendor compromise", malware: "Point-of-sale malware", vulnerabilities: ["HVAC vendor network access", "Weak network segmentation"], tactics: ["Initial Access", "Lateral Movement", "Collection", "Exfiltration"], detectionMethod: "US Department of Justice notification", responseActions: ["Card reissuance", "Credit monitoring", "Security overhaul"], lawEnforcement: "FBI investigation, multiple arrests", outcome: "Security improvements, legal settlements, executive changes", impact: "Critical - 110 million customer records compromised", industry: "Retail", severity: "Critical", references: ["Senate Committee Report", "DOJ Indictments", "Target SEC Filings"], technicalSummary: "Attackers gained access through HVAC vendor credentials, moved laterally to point-of-sale systems, and installed memory-scraping malware to harvest payment card data.", nonTechnicalSummary: "Criminals broke into Target's computer systems through a heating and air conditioning company's access, stealing millions of customers' credit card and personal information.", lessonsLearned: [ "Implement strict third-party vendor security requirements", "Deploy network segmentation and access controls", "Monitor point-of-sale systems for anomalous activity", "Establish comprehensive incident response capabilities" ], opsecFailures: [ "Used easily traceable cryptocurrency transactions", "Left malware artifacts on compromised systems", "Reused infrastructure across multiple retail targets" ], defensiveGaps: [ "Excessive third-party network access", "Insufficient network segmentation", "Limited POS system monitoring" ], featured: true }
          ];
          for (const incident of baseIncidents) {
            try {
              await addDoc(incidentsRef, incident);
            } catch (e) {
              console.error("Error adding document: ", e);
            }
          }
          console.log("Database seeded successfully.");
        } else {
          console.log("Database already contains data. Skipping seed.");
        }
      } catch (error) {
        console.error("Error checking/seeding database: ", error);
      }
    };

    seedDatabase();

  }, [db, isAuthReady, isAdmin]); 

  /* --- Data Fetching Effect --- */
  useEffect(() => {
    if (!db || !isAuthReady) return;

    setIsLoading(true); 
    const incidentsRef = collection(db, "incidents");

    const unsubscribe = onSnapshot(incidentsRef, (querySnapshot) => {
      const incidentsData = [];
      querySnapshot.forEach((doc) => {
        incidentsData.push({ ...doc.data(), docId: doc.id }); // <-- STORE THE FIRESTORE DOC ID
      });
      
      setAllIncidents(incidentsData);
      setIsLoading(false); 
      console.log("Data fetched from Firebase: ", incidentsData.length, " incidents");
    }, (error) => {
      console.error("Error fetching data from snapshot: ", error);
      setIsLoading(false);
    });

    return () => unsubscribe();

  }, [db, isAuthReady]); 

  /* --- Data Definitions --- */
  
  // Memoized Featured Incidents
  const featuredIncidents = useMemo(() => {
    return allIncidents
      .filter(i => i.featured) 
      .sort((a, b) => new Date(b.date) - new Date(a.date));
  }, [allIncidents]); 

  // Memoized Filtered Incidents
  const filteredIncidents = useMemo(() => {
    return allIncidents.filter(incident => {
      const search = searchTerm.toLowerCase();
      const matchesSearch = searchTerm === '' || 
        incident.name.toLowerCase().includes(search) ||
        incident.attackers.toLowerCase().includes(search) ||
        incident.attackVector.toLowerCase().includes(search) ||
        (incident.victims && incident.victims.some(victim => victim.toLowerCase().includes(search)));
      
      let matchesDate = true;  
      if (filters.dateRange === 'recent') {
        matchesDate = new Date(incident.date) > new Date('2020-01-01');
      } else if (filters.dateRange === '2017-2019') {
        matchesDate = new Date(incident.date) >= new Date('2017-01-01') && new Date(incident.date) < new Date('2020-01-01');
      }

      const matchesAttack = filters.attackType === 'all' || incident.attackVector.includes(filters.attackType);
      const matchesIndustry = filters.industry === 'all' || incident.industry.includes(filters.industry);
      const matchesSeverity = filters.severity === 'all' || incident.severity === filters.severity;
      
      return matchesSearch && matchesDate && matchesAttack && matchesIndustry && matchesSeverity;
    })
    .sort((a, b) => new Date(b.date) - new Date(a.date));
    
  }, [allIncidents, searchTerm, filters]); 


  /* --- Main Render Function --- */
  return (
    <div className="min-h-screen bg-black font-sans text-gray-300">
      
      {/* --- Toast Notification Container --- */}
      <Toaster 
        position="top-right"
        toastOptions={{
          style: {
            background: '#1F2937', // gray-800
            color: '#D1D5DB', // gray-300
            border: '1px solid #22c55e', // green-500
          },
        }}
      />
      
      {/* --- Header & Navigation --- */}
      <header className="bg-gray-900 border-b border-green-500/30 shadow-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            
            <div className="flex items-center gap-3 cursor-pointer" onClick={() => handleNavClick('home')}>
              <div className="relative">
                <Database className="w-8 h-8 text-green-400" />
                {isLoading && (
                  <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
                )}
              </div>
              <h1 className="text-xl font-bold text-white font-mono tracking-wider">BREACHARCHIVE</h1>
            </div>
            
            <nav className="flex items-center gap-1 sm:gap-2">
              <NavButton 
                label="HOME" 
                icon={Home}
                isActive={activeView === 'home'} 
                onClick={() => handleNavClick('home')} 
              />
              <NavButton 
                label="INCIDENTS" 
                icon={FileCode}
                isActive={activeView === 'search'} 
                onClick={() => handleNavClick('search')} 
              />
              <NavButton 
                label="ANALYTICS" 
                icon={Activity}
                isActive={activeView === 'analytics'} 
                onClick={() => handleNavClick('analytics')} 
              />
              <NavButton 
                label="ABOUT" 
                icon={User}
                isActive={activeView === 'about'} 
                onClick={() => handleNavClick('about')} 
              />
              <NavButton 
                label="CONTACT" 
                icon={Contact}
                isActive={activeView === 'contact'} 
                onClick={() => handleNavClick('contact')} 
              />
              
              {/* --- Admin/Login/Logout Buttons --- */}
              {isAdmin && (
                <>
                  <NavButton 
                    label="ADMIN" 
                    icon={Lock}
                    isActive={activeView === 'admin'} 
                    onClick={() => handleNavClick('admin')} 
                  />
                  <NavButton 
                    label="LOGOUT" 
                    icon={LogOut}
                    isActive={false} 
                    onClick={handleLogout} 
                  />
                </>
              )}
              
              {!isAdmin && isAuthReady && (
                <NavButton 
                  label="LOGIN" 
                  icon={LogIn}
                  isActive={activeView === 'admin'} 
                  onClick={() => handleNavClick('admin')}
                />
              )}
            </nav>
          </div>
        </div>
      </header>

      {/* --- Main Content Area --- */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* Loading Spinner */}
        {isLoading && ( 
          <div className="flex justify-center items-center h-64">
              <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-green-500"></div>
          </div>
        )}

        {/* Incident Detail View */}
        {isAuthReady && !isLoading && selectedIncident ? (
          <IncidentDetail 
            incident={selectedIncident} 
            onBack={() => setSelectedIncident(null)}
            // --- Pass admin props ---
            isAdmin={isAdmin}
            onEdit={handleEditRequest}
            onDelete={handleDeleteRequest}
          />
        ) : (
          
          /* Page Views */
          isAuthReady && !isLoading && (
            <>
              {activeView === 'home' && (
                <HomePage 
                  featuredIncidents={featuredIncidents} 
                  onViewAll={() => handleNavClick('search')}
                  onIncidentClick={setSelectedIncident}
                  totalIncidents={allIncidents.length}
                  isLoading={isLoading}
                />
              )}
              
              {activeView === 'search' && (
                <SearchInterface
                  filteredIncidents={filteredIncidents}
                  onIncidentClick={setSelectedIncident}
                  searchTerm={searchTerm}
                  onSearchChange={setSearchTerm}
                  filters={filters}
                  onFilterChange={setFilters}
                  visibleCount={visibleIncidentCount}
                  onShowMore={handleShowMore}
                />
              )}
              
              {activeView === 'analytics' && (
                <AnalyticsView allIncidents={allIncidents} />
              )}
              
              {activeView === 'about' && (
                <AboutPage />
              )}
              
              {activeView === 'contact' && (
                <ContactPage />
              )}
              
              {activeView === 'admin' && (
                <AdminPage 
                  db={db} 
                  auth={auth}
                  isAdmin={isAdmin}
                  // --- Pass edit props ---
                  incidentToEdit={incidentToEdit}
                  onIncidentSubmitted={handleIncidentSubmitted}
                  onIncidentUpdated={handleIncidentUpdated}
                  onCancelEdit={handleCancelEdit}
                />
              )}
            </>
          )
        )}
      </main>
      
      {/* --- Delete Confirmation Modal --- */}
      {showDeleteModal && (
        <DeleteConfirmationModal
          incident={incidentToDelete}
          onCancel={handleDeleteCancel}
          onConfirm={handleDeleteConfirm}
        />
      )}
      
      {/* --- Footer --- */}
      <footer className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 border-t border-gray-800 text-center">
        <p className="text-gray-500 font-mono text-sm">
          BreachArchive | Connected to: <span className="text-green-500">{firebaseConfig.projectId || 'LOCAL_ENV'}</span>
        </p>
      </footer>
    </div>
  );
}

/* --- Reusable Components --- */

// A reusable navigation button for the header
const NavButton = ({ label, icon: Icon, isActive, onClick }) => (
  <button 
    onClick={onClick}
    className={`px-3 py-2 rounded-lg font-mono text-sm tracking-wider transition-all flex items-center gap-2 ${
      isActive 
        ? 'bg-green-900/50 border border-green-500/50 text-green-400' 
        : 'text-gray-400 hover:text-green-400'
    }`}
  >
    <Icon className="w-4 h-4" />
    <span className="hidden sm:inline">{label}</span>
  </button>
);

/* --- Admin Page Component --- */
const AdminPage = ({ 
  db, 
  auth, 
  isAdmin, 
  incidentToEdit, 
  onIncidentSubmitted, 
  onIncidentUpdated, 
  onCancelEdit 
}) => {
  
  // --- STATE FOR NEW LOGIN FORM ---
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loginError, setLoginError] = useState(null);
  const [isLoginLoading, setIsLoginLoading] = useState(false);
  
  // --- NEW: Check for Edit Mode ---
  const isEditMode = incidentToEdit !== null;
  
  const [formData, setFormData] = useState({
    name: '', date: '', location: '', victims: '', attackers: '', 
    attackVector: '', malware: '', vulnerabilities: '', tactics: '', 
    detectionMethod: '', responseActions: '', lawEnforcement: '', 
    outcome: '', impact: '', industry: '', severity: 'Medium', 
    references: '', technicalSummary: '', nonTechnicalSummary: '', 
    lessonsLearned: '', opsecFailures: '', defensiveGaps: '', 
    featured: false,
  });
  
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);

  // --- NEW: Effect to pre-fill form in Edit Mode ---
  useEffect(() => {
    if (isEditMode) {
      // We are editing. Fill the form with the incident's data.
      setFormData({
        name: incidentToEdit.name || '',
        date: incidentToEdit.date || '',
        location: incidentToEdit.location || '',
        // Convert arrays back to strings for textareas/inputs
        victims: (incidentToEdit.victims || []).join(', '),
        attackers: incidentToEdit.attackers || '',
        attackVector: incidentToEdit.attackVector || '',
        malware: incidentToEdit.malware || '',
        vulnerabilities: (incidentToEdit.vulnerabilities || []).join(', '),
        tactics: (incidentToEdit.tactics || []).join(', '),
        detectionMethod: incidentToEdit.detectionMethod || '',
        responseActions: (incidentToEdit.responseActions || []).join(', '),
        lawEnforcement: incidentToEdit.lawEnforcement || '',
        outcome: incidentToEdit.outcome || '',
        impact: incidentToEdit.impact || '',
        industry: incidentToEdit.industry || '',
        severity: incidentToEdit.severity || 'Medium',
        references: (incidentToEdit.references || []).join(', '),
        technicalSummary: incidentToEdit.technicalSummary || '',
        nonTechnicalSummary: incidentToEdit.nonTechnicalSummary || '',
        lessonsLearned: (incidentToEdit.lessonsLearned || []).join('\n'),
        opsecFailures: (incidentToEdit.opsecFailures || []).join('\n'),
        defensiveGaps: (incidentToEdit.defensiveGaps || []).join('\n'),
        featured: incidentToEdit.featured || false,
      });
    } else {
      // We are creating. Reset the form to blank.
      setFormData({
        name: '', date: '', location: '', victims: '', attackers: '', 
        attackVector: '', malware: '', vulnerabilities: '', tactics: '', 
        detectionMethod: '', responseActions: '', lawEnforcement: '', 
        outcome: '', impact: '', industry: '', severity: 'Medium', 
        references: '', technicalSummary: '', nonTechnicalSummary: '', 
        lessonsLearned: '', opsecFailures: '', defensiveGaps: '', 
        featured: false,
      });
    }
  }, [incidentToEdit, isEditMode]); // Re-run this when 'incidentToEdit' changes

  
  // --- NEW: Handle Email/Password Login ---
  const handleEmailLogin = async (e) => {
    e.preventDefault();
    if (!auth) return;
    
    setIsLoginLoading(true);
    setLoginError(null);
    
    try {
      await signInWithEmailAndPassword(auth, email, password);
      toast.success("Login successful!"); 
      setIsLoginLoading(false);
    } catch (err) {
      console.error("Error signing in with email/password: ", err);
      if (err.code === 'auth/invalid-credential' || err.code === 'auth/wrong-password' || err.code === 'auth/user-not-found') {
        setLoginError('Invalid email or password.');
        toast.error('Invalid email or password.'); 
      } else {
        setLoginError('An error occurred. Please try again.');
        toast.error('An error occurred. Please try again.'); 
      }
      setIsLoginLoading(false);
    }
  };

  // --- Check if user is admin ---
  if (!isAdmin) {
    return (
      <div className="bg-gray-900 border border-green-500/30 rounded-lg p-8 max-w-lg mx-auto shadow-2xl animate-fadeIn text-center">
        <h2 className="text-3xl font-bold text-green-400 font-mono tracking-wider mb-6 flex items-center justify-center gap-3">
          <Lock className="w-8 h-8" />
          ADMIN ACCESS
        </h2>
        <p className="text-gray-300 mb-8">
          You must be logged in as an administrator to access this page.
        </p>
        
        <form onSubmit={handleEmailLogin} className="space-y-4">
          <AdminInput 
            name="email" 
            label="Email" 
            type="email" 
            value={email} 
            onChange={(e) => setEmail(e.target.value)} 
            required
          />
          <AdminInput 
            name="password" 
            label="Password" 
            type="password" 
            value={password} 
            onChange={(e) => setPassword(e.target.value)} 
            required
          />
          
          {loginError && (
            <p className="text-red-400 font-mono text-sm">{loginError}</p>
          )}
          
          <button
            type="submit"
            disabled={isLoginLoading}
            className="w-full px-6 py-4 bg-green-900/50 border border-green-500/50 text-green-400 rounded-lg hover:bg-green-800/50 font-mono text-sm tracking-wider transition-all disabled:opacity-50"
          >
            {isLoginLoading ? 'LOGGING IN...' : 'LOGIN'}
          </button>
        </form>
      </div>
    );
  }
  
  // --- If user IS an admin, show the form ---
  
  // Handles changes to any form input
  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prevData => ({
      ...prevData,
      [name]: type === 'checkbox' ? checked : value
    }));
  };
  
  // A helper function to split text from textareas into arrays
  const splitByComma = (str) => {
    if (!str) return [];
    return str.split(',').map(item => item.trim()).filter(Boolean);  
  };
  
  const splitByNewline = (str) => {
    if (!str) return [];
    return str.split('\n').map(item => item.trim()).filter(Boolean);
  };
  
  // --- Form Validation Function ---
  const validateForm = () => {
    // 1. Check Name
    if (formData.name.trim().length < 5) {
      toast.error("Incident Name must be at least 5 characters long.");
      return false;
    }
    
    // 2. Check Date
    if (!formData.date) {
      toast.error("Date is a required field.");
      return false;
    }
    // Try to parse the date and check if it's valid
    const d = new Date(formData.date);
    if (isNaN(d.getTime())) {
      toast.error("The date entered is not a valid date.");
      return false;
    }
    
    // 3. Check Summary
    if (formData.nonTechnicalSummary.trim().length < 10) {
      toast.error("Non-Technical Summary must be at least 10 characters long.");
      return false;
    }
    
    // All checks passed
    return true;
  };

  // --- Form Submit Handler ---
  const handleSubmit = async (e) => {
    e.preventDefault(); 
    
    if (!db || !isAdmin) {
      setError("Not authorized or database not ready.");
      return;
    }
    
    // --- Validation Step ---
    if (!validateForm()) {
      return; // Stop submission if validation fails
    }
    
    setIsSubmitting(true);
    setError(null);
    
    // Format the data for Firebase
    const formattedIncident = {
      ...formData,
      victims: splitByComma(formData.victims),
      vulnerabilities: splitByComma(formData.vulnerabilities),
      tactics: splitByComma(formData.tactics),
      responseActions: splitByComma(formData.responseActions),
      references: splitByComma(formData.references),
      lessonsLearned: splitByNewline(formData.lessonsLearned),
      opsecFailures: splitByNewline(formData.opsecFailures),
      defensiveGaps: splitByNewline(formData.defensiveGaps),
    };

    try {
      if (isEditMode) {
        // --- UPDATE ---
        const docId = incidentToEdit.docId;
        if (!docId) throw new Error("Missing Doc ID for update!");
        
        const incidentRef = doc(db, "incidents", docId);
        await updateDoc(incidentRef, formattedIncident);
        
        setIsSubmitting(false);
        console.log('Incident updated successfully!'); 
        toast.success('Incident updated successfully!'); 
        onIncidentUpdated(); // Navigate away
        
      } else {
        // --- CREATE ---
        const incidentsRef = collection(db, "incidents");
        await addDoc(incidentsRef, formattedIncident);
        
        setIsSubmitting(false);
        console.log('Incident added successfully!'); 
        toast.success('Incident added successfully!'); 
        onIncidentSubmitted(); // Navigate away
      }
      
    } catch (err) {
      console.error("Error submitting incident: ", err);
      if (err.code === 'permission-denied') {
        setError('PERMISSION DENIED. Check your Firebase security rules.');
        toast.error('Permission Denied.'); 
      } else {
        setError('Failed to submit incident. Check console for details.');
        toast.error('Failed to submit incident.'); 
      }
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-green-500/30 rounded-lg p-8 max-w-4xl mx-auto shadow-2xl animate-fadeIn">
      <h2 className="text-3xl font-bold text-green-400 font-mono tracking-wider mb-6 flex items-center gap-3">
        {isEditMode ? <Edit className="w-8 h-8" /> : <UploadCloud className="w-8 h-8" />}
        {isEditMode ? 'EDIT INCIDENT' : 'ADD NEW INCIDENT'}
      </h2>
      
      <form onSubmit={handleSubmit} className="space-y-6">
        
        {/* --- Core Info --- */}
        <div className="p-4 border border-gray-700 rounded-lg">
          <h3 className="text-xl font-bold text-green-400 font-mono tracking-wider mb-4">Core Info</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <AdminInput name="name" label="Incident Name" value={formData.name} onChange={handleChange} required />
            <AdminInput name="date" label="Date" type="date" value={formData.date} onChange={handleChange} required />
            <AdminInput name="location" label="Location" value={formData.location} onChange={handleChange} />
            <AdminInput name="attackers" label="Attackers" value={formData.attackers} onChange={handleChange} />
            <AdminInput name="industry" label="Industry" value={formData.industry} onChange={handleChange} />
            <AdminSelect 
              name="severity" 
              label="Severity" 
              value={formData.severity} 
              onChange={handleChange}
              options={['Low', 'Medium', 'High', 'Critical']}
            />
          </div>
          <div className="mt-4">
            <AdminInput name="impact" label="Impact" value={formData.impact} onChange={handleChange} />
          </div>
        </div>

        {/* --- Summaries --- */}
        <div className="p-4 border border-gray-700 rounded-lg">
          <h3 className="text-xl font-bold text-green-400 font-mono tracking-wider mb-4">Summaries</h3>
          <div className="space-y-4">
            <AdminTextarea name="nonTechnicalSummary" label="Non-Technical Summary (Executive)" value={formData.nonTechnicalSummary} onChange={handleChange} required />
            <AdminTextarea name="technicalSummary" label="Technical Summary" value={formData.technicalSummary} onChange={handleChange} />
          </div>
        </div>

        {/* --- Technical Details --- */}
        <div className="p-4 border border-gray-700 rounded-lg">
          <h3 className="text-xl font-bold text-green-400 font-mono tracking-wider mb-4">Technical Details</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <AdminInput name="attackVector" label="Attack Vector" value={formData.attackVector} onChange={handleChange} />
            <AdminInput name="malware" label="Malware / Tools Used" value={formData.malware} onChange={handleChange} />
            <AdminInput name="victims" label="Victims (comma-separated)" value={formData.victims} onChange={handleChange} />
            <AdminInput name="vulnerabilities" label="Vulnerabilities (comma-separated)" value={formData.vulnerabilities} onChange={handleChange} />
            <AdminInput name="tactics" label="Tactics (comma-separated)" value={formData.tactics} onChange={handleChange} />
            <AdminInput name="references" label="References (comma-separated)" value={formData.references} onChange={handleChange} />
          </div>
        </div>

        {/* --- Response --- */}
        <div className="p-4 border border-gray-700 rounded-lg">
          <h3 className="text-xl font-bold text-green-400 font-mono tracking-wider mb-4">Response & Outcome</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <AdminInput name="detectionMethod" label="Detection Method" value={formData.detectionMethod} onChange={handleChange} />
            <AdminInput name="lawEnforcement" label="Law Enforcement" value={formData.lawEnforcement} onChange={handleChange} />
            <AdminInput name="responseActions" label="Response Actions (comma-separated)" value={formData.responseActions} onChange={handleChange} />
            <AdminInput name="outcome" label="Outcome" value={formData.outcome} onChange={handleChange} />
          </div>
        </div>
        
        {/* --- Analysis --- */}
        <div className="p-4 border border-gray-700 rounded-lg">
          <h3 className="text-xl font-bold text-green-400 mb-4 flex items-center gap-2 font-mono tracking-wider">Analysis (One item per line)</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <AdminTextarea name="lessonsLearned" label="Lessons Learned" value={formData.lessonsLearned} onChange={handleChange} rows={5} />
            <AdminTextarea name="opsecFailures" label="Attacker OPSEC Failures" value={formData.opsecFailures} onChange={handleChange} rows={5} />
            <AdminTextarea name="defensiveGaps" label="DefensiveGaps" value={formData.defensiveGaps} onChange={handleChange} rows={5} />
          </div>
        </div>

        {/* --- Submit Button --- */}
        <div className="flex items-center justify-between pt-6 border-t border-gray-700">
          <div className="flex items-center gap-3">
            <input
              type="checkbox"
              name="featured"
              id="featured"
              checked={formData.featured}
              onChange={handleChange}
              className="h-5 w-5 bg-gray-800 border-gray-600 text-green-500 focus:ring-green-500 rounded"
            />
            <label htmlFor="featured" className="font-mono text-green-400">
              Mark as "Featured Incident"
            </label>
          </div>
          
          <div className="flex items-center gap-4">
            {error && <p className="text-red-400 font-mono text-sm">{error}</p>}
            
            {/* --- Cancel Edit Button --- */}
            {isEditMode && (
              <button
                type="button" 
                onClick={onCancelEdit}
                className="px-6 py-3 bg-gray-800 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700 font-mono text-sm tracking-wider transition-all"
              >
                CANCEL
              </button>
            )}
            
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-6 py-3 bg-green-900/50 border border-green-500/50 text-green-400 rounded-lg hover:bg-green-800/50 font-mono text-sm tracking-wider transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting 
                ? (isEditMode ? 'UPDATING...' : 'SUBMITTING...')
                : (isEditMode ? 'UPDATE INCIDENT' : 'SUBMIT INCIDENT')
              }
            </button>
          </div>
        </div>
        
      </form>
    </div>
  );
};

// Helper component for Admin Form Inputs
const AdminInput = ({ name, label, type = 'text', value, onChange, required = false }) => (
  <div className="w-full">
    <label htmlFor={name} className="block text-sm font-mono text-green-400 mb-1">
      {label} {required && <span className="text-red-400">*</span>}
    </label>
    <input
      type={type}
      name={name}
      id={name}
      value={value}
      onChange={onChange}
      required={required}
      className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white font-mono text-sm focus:ring-2 focus:ring-green-500"
    />
  </div>
);

// Helper component for Admin Form Textareas
const AdminTextarea = ({ name, label, value, onChange, required = false, rows = 3 }) => (
  <div className="w-full">
    <label htmlFor={name} className="block text-sm font-mono text-green-400 mb-1">
      {label} {required && <span className="text-red-400">*</span>}
    </label>
    <textarea
      name={name}
      id={name}
      value={value}
      onChange={onChange}
      required={required}
      rows={rows}
      className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white font-mono text-sm focus:ring-2 focus:ring-green-500"
    />
  </div>
);

// Helper component for Admin Form Selects
const AdminSelect = ({ name, label, value, onChange, options, required = false }) => (
  <div className="w-full">
    <label htmlFor={name} className="block text-sm font-mono text-green-400 mb-1">
      {label} {required && <span className="text-red-400">*</span>}
    </label>
    <select
      name={name}
      id={name}
      value={value}
      onChange={onChange}
      required={required}
      className="w-full px-3 py-3 bg-gray-800 border border-gray-600 rounded-lg text-white font-mono text-sm focus:ring-2 focus:ring-green-500 appearance-none"
      style={{
        backgroundImage: 'url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%2322c55e\' stroke-width=\'2\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3e%3cpolyline points=\'6 9 12 15 18 9\'%3e%3c/polyline%3e%3c/svg%3e")',
        backgroundRepeat: 'no-repeat',
        backgroundPosition: 'right 0.75rem center',
        backgroundSize: '1.25em 1.25em'
      }}
    >
      {options.map(option => (
        <option key={option} value={option}>{option}</option>
      ))}
    </select>
  </div>
);

/* --- Home Page Component --- */
const HomePage = ({ featuredIncidents, onViewAll, onIncidentClick, totalIncidents, isLoading }) => (
  <div className="space-y-8 animate-fadeIn">
    {/* Hero Section */}
    <div className="bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 border border-green-500/30 rounded-lg p-8 shadow-2xl">
      <div className="text-center">
        <div className="flex items-center justify-center gap-3 mb-4">
          <Lock className="w-12 h-12 text-green-400" />
          <h1 className="text-4xl font-bold text-green-400 font-mono tracking-wider">BREACHARCHIVE</h1>
        </div>
        <p className="text-xl text-gray-300 mb-6 font-mono">
          A live database of major cybersecurity incidents and threat intelligence.
        </p>
        <div className="flex items-center justify-center gap-6 text-sm font-mono text-gray-400">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-green-400" />
            <span>{isLoading ? '...' : totalIncidents} TOTAL INCIDENTS</span>
          </div>
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-green-400" />
            <span>REAL-TIME ANALYSIS</span>
          </div>
          <div className="flex items-center gap-2">
            <Brain className="w-4 h-4 text-green-400" />
            <span>THREAT INTELLIGENCE</span>
          </div>
        </div>
      </div>
    </div>

    {/* Featured Incidents */}
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-green-400 font-mono tracking-wider">FEATURED INCIDENTS</h2>
        <button 
          onClick={onViewAll}
          className="px-4 py-2 bg-green-900/50 border border-green-500/50 text-green-400 rounded-lg hover:bg-green-800/50 font-mono text-sm tracking-wider transition-all"
        >
          VIEW ALL →
        </button>
      </div>
      
      {isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="bg-gray-900 border border-green-500/30 rounded-lg p-6 animate-pulse">
                  <div className="h-6 bg-gray-700 rounded w-3/4 mb-4"></div>
                  <div className="h-4 bg-gray-700 rounded w-1/4 mb-4"></div>
                  <div className="space-y-2">
                    <div className="h-4 bg-gray-700 rounded w-full"></div>
                    <div className="h-4 bg-gray-700 rounded w-5/6"></div>
                  </div>
                </div>
              ))}
            </div>
        ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {featuredIncidents.length > 0 ? (
            featuredIncidents.map(incident => (
              <IncidentSummaryCard 
                key={incident.docId || incident.id} 
                incident={incident} 
                onIncidentClick={onIncidentClick} 
              />
            ))
          ) : (
            <p className="text-gray-400 font-mono col-span-3">No featured incidents found.</p>
          )}
        </div>
      )}
    </div>
  </div>
);

/* --- Search Page Component --- */
const SearchInterface = ({ 
  filteredIncidents, onIncidentClick, searchTerm, onSearchChange, 
  filters, onFilterChange, visibleCount, onShowMore 
}) => (
  <div className="space-y-6 animate-fadeIn">
    {/* Search & Filter Bar */}
    <div className="bg-gray-900 border border-green-500/30 rounded-lg p-6 shadow-lg">
      <div className="flex flex-col md:flex-row items-center gap-4 mb-6">
        <div className="flex-1 relative w-full">
          <Search className="absolute left-4 top-4 w-5 h-5 text-green-400" />
          <input
            type="text"
            placeholder="Search incidents by name, attacker, attack vector, or victim..."
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full pl-12 pr-4 py-4 bg-gray-800 border border-gray-600 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent text-white placeholder-gray-400 font-mono"
          />
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Date Range Filter */}
        <select 
          value={filters.dateRange} 
          onChange={(e) => onFilterChange({...filters, dateRange: e.target.value})}
          className="px-3 py-3 bg-gray-800 border border-gray-600 rounded-lg text-white font-mono text-sm focus:ring-2 focus:ring-green-500 appearance-none"
          style={{ backgroundImage: 'url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%2322c55e\' stroke-width=\'2\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3e%3cpolyline points=\'6 9 12 15 18 9\'%3e%3c/polyline%3e%3c/svg%3e")', backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.75rem center', backgroundSize: '1.25em 1.25em' }}
        >
          <option value="all">All Time</option>
          <option value="recent">2020-Present</option>
          <option value="2017-2019">2017-2019</option>
        </select>
        {/* Attack Type Filter */}
        <select 
          value={filters.attackType} 
          onChange={(e) => onFilterChange({...filters, attackType: e.target.value})}
          className="px-3 py-3 bg-gray-800 border border-gray-600 rounded-lg text-white font-mono text-sm focus:ring-2 focus:ring-green-500 appearance-none"
          style={{ backgroundImage: 'url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%2322c55e\' stroke-width=\'2\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3e%3cpolyline points=\'6 9 12 15 18 9\'%3e%3c/polyline%3e%3c/svg%3e")', backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.75rem center', backgroundSize: '1.25em 1.25em' }}
        >
          <option value="all">All Attack Types</option>
          <option value="Phishing">Phishing</option>
          <option value="Ransomware">Ransomware</option>
          <option value="Supply Chain">Supply Chain</option>
          <option value="Web Application">Web Application</option>
          <option value="DDoS">DDoS</option>
          <option value="Malware">Malware</option>
        </select>
        {/* Industry Filter */}
        <select 
          value={filters.industry} 
          onChange={(e) => onFilterChange({...filters, industry: e.target.value})}
          className="px-3 py-3 bg-gray-800 border border-gray-600 rounded-lg text-white font-mono text-sm focus:ring-2 focus:ring-green-500 appearance-none"
          style={{ backgroundImage: 'url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%2322c55e\' stroke-width=\'2\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3e%3cpolyline points=\'6 9 12 15 18 9\'%3e%3c/polyline%3e%3c/svg%3e")', backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.75rem center', backgroundSize: '1.25em 1.25em' }}
        >
          <option value="all">All Industries</option>
          <option value="Healthcare">Healthcare</option>
          <option value="Financial Services">Financial Services</option>
          <option value="Government">Government</option>
          <option value="Technology">Technology</option>
          <option value="Education">Education</option>
          <option value="Retail">Retail</option>
          <option value="Energy">Energy</option>
        </select>
        {/* Severity Filter */}
        <select 
          value={filters.severity} 
          onChange={(e) => onFilterChange({...filters, severity: e.target.value})}
          className="px-3 py-3 bg-gray-800 border border-gray-600 rounded-lg text-white font-mono text-sm focus:ring-2 focus:ring-green-500 appearance-none"
          style={{ backgroundImage: 'url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%2322c55e\' stroke-width=\'2\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3e%3cpolyline points=\'6 9 12 15 18 9\'%3e%3c/polyline%3e%3c/svg%3e")', backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.75rem center', backgroundSize: '1.25em 1.25em' }}
        >
          <option value="all">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>
    </div>

    {/* Incident Cards Grid */}
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      {filteredIncidents.slice(0, visibleCount).map(incident => (
        <IncidentSummaryCard 
          key={incident.docId || incident.id} 
          incident={incident} 
          onIncidentClick={onIncidentClick} 
        />
      ))}
    </div>

    {/* No Results Message */}
    {filteredIncidents.length === 0 && (
      <div className="text-center py-12">
        <Terminal className="w-16 h-16 text-green-400/50 mx-auto mb-4" />
        <h3 className="text-lg font-mono text-green-400 mb-2 tracking-wider">NO INCIDENTS FOUND</h3>
        <p className="text-gray-400 font-mono">Try adjusting your search parameters</p>
      </div>
    )}
    
    {/* Show More Button */}
    {visibleCount < filteredIncidents.length && (
      <div className="text-center mt-8">
        <button
          onClick={onShowMore}
          className="px-6 py-3 bg-green-900/50 border border-green-500/50 text-green-400 rounded-lg hover:bg-green-800/50 font-mono text-sm tracking-wider transition-all"
        >
          SHOW MORE ({filteredIncidents.length - visibleCount} remaining)
        </button>
      </div>
    )}
  </div>
);

/* --- Incident Summary Card Component (for Home & Search) --- */
const IncidentSummaryCard = ({ incident, onIncidentClick }) => (
  <div 
    className="bg-gray-900 border border-green-500/30 rounded-lg p-6 hover:border-green-400/50 transition-all cursor-pointer shadow-lg hover:shadow-green-500/10 h-full flex flex-col justify-between animate-fadeIn"
    onClick={() => onIncidentClick(incident)}
  >
    <div>
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-xl font-bold text-green-400 font-mono tracking-wider">{incident.name}</h3>
        <div className="flex items-center gap-2">
          <span className={`flex-shrink-0 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest border ${
            incident.severity === 'Critical' ? 'bg-red-900/50 text-red-400 border-red-500/50' :
            incident.severity === 'High' ? 'bg-orange-900/50 text-orange-400 border-orange-500/50' :
            incident.severity === 'Medium' ? 'bg-yellow-900/50 text-yellow-400 border-yellow-500/50' :
            'bg-green-900/50 text-green-400 border-green-500/50'
          }`}>
            {incident.severity}
          </span>
        </div>
      </div>
      
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div className="flex items-center gap-2 text-gray-300">
          <Calendar className="w-4 h-4 text-green-400" />
          <span className="font-mono text-sm">{incident.date}</span>
        </div>
        <div className="flex items-center gap-2 text-gray-300">
          <MapPin className="w-4 h-4 text-green-400" />
          <span className="font-mono text-sm">{incident.location}</span>
        </div>
        <div className="flex items-center gap-2 text-gray-300">
          <Users className="w-4 h-4 text-green-400" />
          <span className="font-mono text-sm truncate">{incident.attackers}</span>
        </div>
        <div className="flex items-center gap-2 text-gray-300">
          <Shield className="w-4 h-4 text-green-400" />
          <span className="font-mono text-sm truncate">{incident.attackVector}</span>
        </div>
      </div>
      
      <div className="border-t border-gray-700 pt-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          {incident.nonTechnicalSummary}
        </p>
      </div>
    </div>
    
    <div className="mt-4 flex items-center justify-between">
      <span className="text-green-400 font-mono text-xs uppercase tracking-widest">
        {incident.industry}
      </span>
      <div className="flex items-center gap-1 text-green-400">
        <Eye className="w-4 h-4" />
        <span className="font-mono text-xs">VIEW DETAILS</span>
      </div>
    </div>
  </div>
);

/* --- Incident Detail Page Component --- */
const IncidentDetail = ({ incident, onBack, isAdmin, onEdit, onDelete }) => {
  const [showFullDetails, setShowFullDetails] = useState(false);

  return (
    <div className="bg-gray-900 border border-green-500/30 rounded-lg p-6 sm:p-8 max-w-6xl mx-auto shadow-2xl animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-8">
        <div>
          <h2 className="text-3xl font-bold text-green-400 font-mono tracking-wider mb-2">{incident.name}</h2>
          <div className="flex items-center gap-4">
            <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest border ${
              incident.severity === 'Critical' ? 'bg-red-900/50 text-red-400 border-red-500/50' :
              incident.severity === 'High' ? 'bg-orange-900/50 text-orange-400 border-orange-500/50' :
              incident.severity === 'Medium' ? 'bg-yellow-900/50 text-yellow-400 border-yellow-500/50' :
              'bg-green-900/50 text-green-400 border-green-500/50'
            }`}>
              {incident.severity}
            </span>
            <span className="text-gray-400 font-mono text-sm">{incident.industry}</span>
          </div>
        </div>
        <div className="flex gap-3 mt-4 sm:mt-0 flex-wrap">
          <button 
            onClick={() => setShowFullDetails(!showFullDetails)}
            className="px-4 py-2 bg-green-900/50 border border-green-500/50 text-green-400 rounded-lg hover:bg-green-800/50 font-mono text-sm tracking-wider transition-all"
          >
            {showFullDetails ? 'HIDE DETAILS' : 'FULL ANALYSIS'}
          </button>
          
          {/* --- ADMIN BUTTONS --- */}
          {isAdmin && (
            <>
              <button 
                onClick={() => onEdit(incident)}
                className="px-4 py-2 bg-blue-900/50 border border-blue-500/50 text-blue-400 rounded-lg hover:bg-blue-800/50 font-mono text-sm tracking-wider transition-all flex items-center gap-2"
              >
                <Edit className="w-4 h-4" />
                EDIT
              </button>
              <button 
                onClick={() => onDelete(incident)}
                className="px-4 py-2 bg-red-900/50 border border-red-500/50 text-red-400 rounded-lg hover:bg-red-800/50 font-mono text-sm tracking-wider transition-all flex items-center gap-2"
              >
                <Trash2 className="w-4 h-4" />
                DELETE
              </button>
            </>
          )}

          <button 
            onClick={onBack} 
            className="px-4 py-2 bg-gray-800 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700 font-mono text-sm tracking-wider transition-all"
          >
            BACK
          </button>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="mb-8">
        <h3 className="font-bold text-green-400 mb-4 flex items-center gap-2 font-mono tracking-wider">
          <Terminal className="w-5 h-5" />
          EXECUTIVE SUMMARY
        </h3>
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
          <p className="text-gray-300 leading-relaxed text-lg">
            {incident.nonTechnicalSummary}
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-gray-700">
            <div>
              <div className="text-green-400 font-mono text-xs uppercase tracking-widest mb-1">Date</div>
              <div className="text-white font-mono">{incident.date}</div>
            </div>
            <div>
              <div className="text-green-400 font-mono text-xs uppercase tracking-widest mb-1">Location</div>
              <div className="text-white font-mono">{incident.location}</div>
            </div>
            <div>
              <div className="text-green-400 font-mono text-xs uppercase tracking-widest mb-1">Impact</div>
              <div className="text-white font-mono text-sm">{incident.impact}</div>
            </div>
            <div>
              <div className="text-green-400 font-mono text-xs uppercase tracking-widest mb-1">Attacker</div>
              <div className="text-white font-mono text-sm">{incident.attackers}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Full Details (Conditional) */}
      {showFullDetails && (
        <div className="space-y-8 animate-fadeIn">
          {/* Technical Analysis */}
          <div>
            <h3 className="font-bold text-green-400 mb-4 flex items-center gap-2 font-mono tracking-wider">
              <Brain className="w-5 h-5" />
              TECHNICAL ANALYSIS
            </h3>
            <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
              <p className="text-gray-300 leading-relaxed mb-6">
                {incident.technicalSummary}
              </p>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-green-400 font-mono text-sm uppercase tracking-widest mb-3">Attack Vector</h4>
                  <div className="space-y-2 text-sm">
                    <div className="text-gray-400">Method: <span className="text-white font-mono">{incident.attackVector}</span></div>
                    <div className="text-gray-400">Malware: <span className="text-white font-mono">{incident.malware}</span></div>
                    <div className="text-gray-400">Vulnerabilities: <span className="text-white">{incident.vulnerabilities?.join(', ')}</span></div>
                    <div className="text-gray-400">Tactics: <span className="text-white">{incident.tactics?.join(', ')}</span></div>
                  </div>
                </div>

                <div>
                  <h4 className="text-green-400 font-mono text-sm uppercase tracking-widest mb-3">Response</h4>
                  <div className="space-y-2 text-sm">
                    <div className="text-gray-400">Detection: <span className="text-white">{incident.detectionMethod}</span></div>
                    <div className="text-gray-400">Actions: <span className="text-white">{incident.responseActions?.join(', ')}</span></div>
                    <div className="text-gray-400">Law Enforcement: <span className="text-white">{incident.lawEnforcement}</span></div>
                    <div className="text-gray-400">Outcome: <span className="text-white">{incident.outcome}</span></div>
                  </div>
                </div>
              </div>

              <div className="mt-6 pt-6 border-t border-gray-700">
                <h4 className="text-green-400 font-mono text-sm uppercase tracking-widest mb-3">Affected Entities</h4>
                <div className="flex flex-wrap gap-2">
                  {incident.victims?.map((victim, idx) => (
                    <span key={idx} className="px-3 py-1 bg-red-900/30 border border-red-500/30 text-red-400 text-xs rounded-full font-mono">
                      {victim}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Lessons Learned & Analysis */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div>
              <h3 className="font-bold text-green-400 mb-4 flex items-center gap-2 font-mono tracking-wider">
                <TrendingUp className="w-5 h-5" />
                LESSONS LEARNED
              </h3>
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
                <ul className="space-y-3">
                  {incident.lessonsLearned?.map((lesson, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-sm">
                      <Zap className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300">{lesson}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div>
              <h3 className="font-bold text-red-400 mb-4 flex items-center gap-2 font-mono tracking-wider">
                <AlertTriangle className="w-5 h-5" />
                OPSEC FAILURES
              </h3>
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
                <ul className="space-y-3">
                  {incident.opsecFailures?.map((failure, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-sm">
                      <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300">{failure}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div>
              <h3 className="font-bold text-orange-400 mb-4 flex items-center gap-2 font-mono tracking-wider">
                <Shield className="w-5 h-5" />
                DEFENSIVE GAPS
              </h3>
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
                <ul className="space-y-3">
                  {incident.defensiveGaps?.map((gap, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-sm">
                      <Shield className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300">{gap}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* References */}
          <div>
            <h3 className="font-bold text-green-400 mb-4 flex items-center gap-2 font-mono tracking-wider">
              <Book className="w-5 h-5" />
              REFERENCES & SOURCES
            </h3>
            <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
              <div className="flex flex-wrap gap-2">
                {incident.references?.map((ref, idx) => (
                  <span key={idx} className="px-3 py-1 bg-blue-900/30 border border-blue-500/30 text-blue-400 text-xs rounded-full font-mono">
                    {ref}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

/* --- Analytics Page Component --- */
const AnalyticsView = ({ allIncidents }) => {
  
  // 1. Data for Severity Pie Chart
  const severityData = useMemo(() => {
    const counts = { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0 };
    allIncidents.forEach(i => {
      if (counts[i.severity] !== undefined) {
        counts[i.severity]++;
      }
    });
    return [
      { name: 'Critical', value: counts['Critical'] },
      { name: 'High', value: counts['High'] },
      { name: 'Medium', value: counts['Medium'] },
      { name: 'Low', value: counts['Low'] },
    ].filter(entry => entry.value > 0);  
  }, [allIncidents]);

  const SEVERITY_COLORS = {
    'Critical': '#ef4444', // red-500
    'High': '#f97316',    // orange-500
    'Medium': '#eab308',   // yellow-500
    'Low': '#22c55e',      // green-500
  };

  // 2. Data for Top Attack Vectors Bar Chart
  const vectorData = useMemo(() => {
    const counts = {};
    allIncidents.forEach(i => {
      const vector = i.attackVector || "Unknown";
      counts[vector] = (counts[vector] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)  
      .slice(0, 10);  
  }, [allIncidents]);

  // 3. Data for Top Industries Bar Chart
  const industryData = useMemo(() => {
    const counts = {};
    allIncidents.forEach(i => {
      const industry = i.industry || "Unknown";
      counts[industry] = (counts[industry] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [allIncidents]);

  // --- 4. Data for Incidents Over Time Line Chart ---
  const timelineData = useMemo(() => {
    const counts = {};
    allIncidents.forEach(i => {
      // Ensure date is valid
      if (i.date) {
        const year = new Date(i.date).getFullYear();
        if (year) {
          counts[year] = (counts[year] || 0) + 1;
        }
      }
    });
    // Convert to array and sort by year
    return Object.entries(counts)
      .map(([year, count]) => ({ year, count }))
      .sort((a, b) => a.year - b.year);
  }, [allIncidents]);

  // Custom Tooltip for Charts
  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-gray-900 border border-green-500/50 p-3 rounded-lg shadow-lg">
          <p className="font-mono text-green-400">{label}</p>
          {/* Support both bar and line chart tooltips */}
          <p className="font-mono text-white">{`${payload[0].name}: ${payload[0].value}`}</p>
        </div>
      );
    }
    return null;
  };
  
  // Custom Pie Chart Label
  const RADIAN = Math.PI / 180;
  const renderCustomizedLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, index, name }) => {
    // A smaller radius to fit text better
    const radius = innerRadius + (outerRadius - innerRadius) * 0.4;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    // Only render label if percent is large enough
    if (percent < 0.05) return null; 

    return (
      <text x={x} y={y} fill="white" textAnchor={x > cx ? 'start' : 'end'} dominantBaseline="central" className="font-mono text-xs font-bold pointer-events-none">
        {`${(percent * 100).toFixed(0)}%`}
      </text>
    );
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-gray-900 border border-green-500/30 rounded-lg p-6">
          <h3 className="font-bold text-green-400 mb-2 font-mono tracking-wider">TOTAL INCIDENTS</h3>
          <p className="text-3xl font-bold text-white font-mono">{allIncidents.length.toLocaleString()}</p>
          <p className="text-sm text-gray-400 mt-1 font-mono">Live database count</p>
        </div>
        <div className="bg-gray-900 border border-red-500/30 rounded-lg p-6">
          <h3 className="font-bold text-red-400 mb-2 font-mono tracking-wider">CRITICAL SEVERITY</h3>
          <p className="text-3xl font-bold text-white font-mono">
            {allIncidents.filter(i => i.severity === 'Critical').length}
          </p>
          <p className="text-sm text-gray-400 mt-1 font-mono">High-impact incidents</p>
        </div>
        <div className="bg-gray-900 border border-blue-500/30 rounded-lg p-6">
          <h3 className="font-bold text-blue-400 mb-2 font-mono tracking-wider">RECENT (2020+)</h3>
          <p className="text-3xl font-bold text-white font-mono">
            {allIncidents.filter(i => new Date(i.date) >= new Date('2020-01-01')).length}
          </p>
          <p className="text-sm text-gray-400 mt-1 font-mono">Modern threats</p>
        </div>
        <div className="bg-gray-900 border border-yellow-500/30 rounded-lg p-6">
          <h3 className="font-bold text-yellow-400 mb-2 font-mono tracking-wider">INDUSTRIES</h3>
          <p className="text-3xl font-bold text-white font-mono">
            {new Set(allIncidents.map(i => i.industry).filter(Boolean)).size}
          </p>
          <p className="text-sm text-gray-400 mt-1 font-mono">Sector diversity</p>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Severity Distribution Pie Chart */}
        <div className="bg-gray-900 border border-green-500/30 rounded-lg p-6 h-[400px]">
          <h3 className="font-bold text-green-400 mb-4 font-mono tracking-wider">INCIDENTS BY SEVERITY</h3>
          <ResponsiveContainer width="100%" height="90%">
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={renderCustomizedLabel}
                outerRadius={130}
                innerRadius={60}
                fill="#8884d8"
                dataKey="value"
                nameKey="name"
                paddingAngle={2}
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name]} stroke={SEVERITY_COLORS[entry.name]} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend 
                layout="vertical" 
                align="right" 
                verticalAlign="middle"
                formatter={(value) => <span className="text-white font-mono">{value}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        
        {/* Top Attack Vectors Bar Chart */}
        <div className="bg-gray-900 border border-blue-500/30 rounded-lg p-6 h-[400px]">
          <h3 className="font-bold text-blue-400 mb-4 font-mono tracking-wider">TOP 10 ATTACK VECTORS</h3>
          <ResponsiveContainer width="100%" height="90%">
            <BarChart data={vectorData} layout="vertical" margin={{ left: 50, right: 20 }}>
              <XAxis type="number" hide />
              <YAxis 
                type="category" 
                dataKey="name" 
                stroke="#9ca3af" 
                className="font-mono text-xs" 
                interval={0}
                width={120}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(59, 130, 246, 0.1)' }}/>
              <Bar dataKey="count" name="Incidents" fill="#3b82f6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

      </div>
      
      {/* Top Industries Chart */}
       <div className="bg-gray-900 border border-yellow-500/30 rounded-lg p-6 h-[400px]">
          <h3 className="font-bold text-yellow-400 mb-4 font-mono tracking-wider">TOP 10 INDUSTRIES AFFECTED</h3>
          <ResponsiveContainer width="100%" height="90%">
            <BarChart data={industryData} layout="vertical" margin={{ left: 50, right: 20 }}>
              <XAxis type="number" hide />
              <YAxis 
                type="category" 
                dataKey="name" 
                stroke="#9ca3af" 
                className="font-mono text-xs" 
                interval={0}
                width={120}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(234, 179, 8, 0.1)' }}/>
              <Bar dataKey="count" name="Incidents" fill="#eab308" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      
      {/* --- Incidents Over Time Line Chart --- */}
      <div className="bg-gray-900 border border-purple-500/30 rounded-lg p-6 h-[400px]">
        <h3 className="font-bold text-purple-400 mb-4 font-mono tracking-wider">INCIDENTS OVER TIME</h3>
        <ResponsiveContainer width="100%" height="90%">
          <LineChart data={timelineData} margin={{ top: 5, right: 20, left: -20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis 
              dataKey="year" 
              stroke="#9ca3af" 
              className="font-mono text-xs" 
            />
            <YAxis 
              stroke="#9ca3af" 
              className="font-mono text-xs"
              allowDecimals={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ stroke: '#8b5cf6', strokeWidth: 1, strokeDasharray: '3 3' }} />
            <Line 
              type="monotone" 
              dataKey="count" 
              name="Incidents" 
              stroke="#a855f7" // purple-500
              strokeWidth={2} 
              activeDot={{ r: 8, strokeWidth: 2, fill: '#a855f7' }} 
              dot={{ r: 4, strokeWidth: 1, fill: '#a855f7' }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

    </div>
  );
};


/* --- About Page Component --- */
const AboutPage = () => (
  <div className="bg-gray-900 border border-green-500/30 rounded-lg p-8 max-w-4xl mx-auto shadow-2xl animate-fadeIn">
    <h2 className="text-3xl font-bold text-green-400 font-mono tracking-wider mb-6">ABOUT BREACHARCHIVE</h2>
    <div className="space-y-6 text-gray-300 leading-relaxed">
      <p>
        Welcome to BreachArchive, a dedicated project built to catalog, analyze, and educate on the most significant cybersecurity incidents in modern history. This tool was born from a passion for cybersecurity and a desire to create a centralized, clean, and accessible database for students, professionals, and enthusiasts alike.
      </p>
      <p>
        Our mission is to provide clear, concise, and technically accurate information on major breaches. By compiling data on attack vectors, threat actors, defensive gaps, and lessons learned, we hope to provide a valuable resource for understanding the threat landscape.
      </p>
      <h3 className="text-2xl font-bold text-green-400 font-mono tracking-wider pt-4 border-t border-gray-700">Technology Stack</h3>
      <ul className="list-disc list-inside space-y-2 font-mono">
        <li><span className="text-green-400">Frontend:</span> React.js & Tailwind CSS</li>
        <li><span className="text-green-400">Database:</span> Google Firebase Firestore</li>
        <li><span className="text-green-400">Authentication:</span> Google Firebase Auth</li>
        <li><span className="text-green-400">Charting:</span> Recharts</li>
        <li><span className="text-green-400">Icons:</span> Lucide React</li>
      </ul>
    </div>
  </div>
);

/* --- Contact Page Component --- */
const ContactPage = () => (
  <div className="bg-gray-900 border border-green-500/30 rounded-lg p-8 max-w-4xl mx-auto shadow-2xl animate-fadeIn">
    <h2 className="text-3xl font-bold text-green-400 font-mono tracking-wider mb-6">CONTACT</h2>
    <div className="space-y-6 text-gray-300 leading-relaxed">
      <p>
        This project is actively maintained. If you have questions, suggestions, or would like to contribute data, please feel free to reach out.
      </p>
      <p>
        (This is a placeholder. You can replace this with your actual contact info, like a link to your LinkedIn, GitHub, or a professional email address.)
      </p>
      <div className="font-mono text-center pt-4">
        <a 
          href="#" 
          className="inline-block px-6 py-3 bg-green-900/50 border border-green-500/50 text-green-400 rounded-lg hover:bg-green-800/50 transition-all"
        >
          CONNECT ON GITHUB (EXAMPLE)
        </a>
      </div>
    </div>
  </div>
);

/* --- Delete Confirmation Modal Component --- */
const DeleteConfirmationModal = ({ incident, onCancel, onConfirm }) => (
  // Full-screen overlay
  <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 animate-fadeIn">
    {/* Modal Box */}
    <div className="bg-gray-900 border border-red-500/30 rounded-lg p-8 max-w-lg mx-4 shadow-2xl">
      <div className="flex items-center gap-3 mb-4">
        <AlertTriangle className="w-10 h-10 text-red-500 flex-shrink-0" />
        <h2 className="text-2xl font-bold text-red-400 font-mono tracking-wider">CONFIRM DELETION</h2>
      </div>
      
      <p className="text-gray-300 mb-2">
        Are you absolutely sure you want to delete this incident?
      </p>
      <p className="bg-gray-800/50 border border-gray-700 p-3 rounded-lg text-white font-mono mb-6">
        {incident?.name}
      </p>
      <p className="text-red-400/80 text-sm mb-6">
        This action is permanent and cannot be undone.
      </p>
      
      {/* Action Buttons */}
      <div className="flex justify-end gap-4">
        <button
          onClick={onCancel}
          className="px-6 py-3 bg-gray-800 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700 font-mono text-sm tracking-wider transition-all"
        >
          CANCEL
        </button>
        <button
          onClick={onConfirm}
          className="px-6 py-3 bg-red-900/50 border border-red-500/50 text-red-400 rounded-lg hover:bg-red-800/50 font-mono text-sm tracking-wider transition-all"
        >
          CONFIRM DELETE
        </button>
      </div>
    </div>
  </div>
);