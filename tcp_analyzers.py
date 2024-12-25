# tcp_analyzers.py

import subprocess
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import os
import traceback
import sys

class LBNLAnalyzer:
    def __init__(self):
        # Internal configuration
        self.config = {
            'anomaly_threshold': 1000,
            'start_date': '2004/10/04:20',
            'end_date': '2005/01/08:05',
            'bin_size': 60  # seconds
        }
        
        # Set configuration values
        self.anomaly_threshold = self.config['anomaly_threshold']
        self.start_date = self.config['start_date']
        self.end_date = self.config['end_date']
        self.bin_size = self.config['bin_size']
        
        # Setup output directory
        self.output_dir = 'output'
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Verify environment
        self._verify_environment()
    
    def _verify_environment(self):
        """Verify SiLK environment setup"""
        print("\nVerifying environment setup:")
        silk_data_dir = os.environ.get('SILK_DATA_ROOTDIR')
        silk_config = os.environ.get('SILK_CONFIG_FILE')
        
        print(f"SILK_DATA_ROOTDIR = {silk_data_dir}")
        print(f"SILK_CONFIG_FILE = {silk_config}")
        
        if not silk_data_dir or not silk_config:
            print("Warning: SiLK environment variables not fully set")
        
        if silk_data_dir and not os.path.exists(silk_data_dir):
            print(f"Warning: SILK_DATA_ROOTDIR {silk_data_dir} does not exist")
        
        if silk_config and not os.path.exists(silk_config):
            print(f"Warning: SILK_CONFIG_FILE {silk_config} does not exist")

    def test_silk_command(self):
        """Test basic SiLK command functionality"""
        try:
            cmd = ['rwfilter', '--version']
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(f"\nTesting rwfilter: {result.stdout.strip()}")
            return True
        except Exception as e:
            print(f"Error testing rwfilter: {e}")
            return False

    def fetch_tcp_data(self):
        """Fetch TCP traffic data from LBNL dataset"""
        print("\nFetching TCP traffic data...")
        
        # First, verify we can access the data
        verify_cmd = [
            'rwfilter',
            f'--start-date={self.start_date}',
            f'--end-date={self.end_date}',
            '--sensor=S0',
            '--type=all',
            '--proto=6',
            '--print-statistics'
        ]
        
        try:
            print("Verifying data access...")
            verify_result = subprocess.run(' '.join(verify_cmd), shell=True, capture_output=True, text=True)
            print(verify_result.stdout)
            
            # Now get the actual data
            cmd = [
                'rwfilter',
                f'--start-date={self.start_date}',
                f'--end-date={self.end_date}',
                '--sensor=S0',
                '--type=all',
                '--proto=6',
                '--pass=stdout',
                '|',
                'rwstats',
                '--fields=stime',
                '--values=packets,bytes',
                '--count=0',
                '--bin-size=60',
                '--delimited=|'
            ]
            
            print("Executing command:", ' '.join(cmd))
            result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True)
            
            if result.stderr:
                print("Command produced errors:", result.stderr)
            
            if not result.stdout:
                print("No output produced, trying alternative command...")
                # Try with different options
                cmd = [
                    'rwfilter',
                    f'--start-date={self.start_date}',
                    f'--end-date={self.end_date}',
                    '--sensor=S0',
                    '--type=all',
                    '--proto=6',
                    '--pass=stdout',
                    '|',
                    'rwuniq',
                    '--fields=sTime',
                    '--values=packets,bytes',
                    '--bin-time=60'
                ]
                print("Executing alternative command:", ' '.join(cmd))
                result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True)
            
            if result.stdout:
                print("\nSample of raw output:")
                print(result.stdout[:500])
                return self.parse_rwcount_output(result.stdout)
            else:
                print("No data received from rwfilter")
                return None
                
        except Exception as e:
            print(f"Error executing rwfilter command: {e}")
            traceback.print_exc()
            return None

    def parse_rwcount_output(self, output):
        """Parse output into DataFrame"""
        print("\nParsing output...")
        records = []
        
        for line in output.split('\n'):
            if line and not line.startswith('#'):
                try:
                    parts = line.strip().split('|')
                    if len(parts) >= 2:
                        record = {
                            'timestamp': pd.to_datetime(parts[0].strip()),
                            'packets': int(float(parts[1].strip()) if len(parts) > 1 else 0)
                        }
                        if len(parts) > 2:
                            record['bytes'] = int(float(parts[2].strip()))
                        records.append(record)
                except Exception as e:
                    print(f"Error parsing line '{line}': {e}")
                    continue
        
        if not records:
            print("No records were successfully parsed")
            return None
        
        df = pd.DataFrame(records)
        df = df.sort_values('timestamp')
        print(f"\nSuccessfully parsed {len(df)} records")
        print("\nSample of parsed data:")
        print(df.head())
        return df

    def classify_traffic(self, df):
        """Classify traffic into different categories"""
        print("\nClassifying traffic...")
        
        # Define traffic ranges (packets per minute)
        ranges = [
            (0, 600),       # Low traffic
            (601, 6000),    # Medium traffic
            (6001, 60000),  # High traffic
            (60001, float('inf'))  # Very high traffic
        ]
        
        # Add classification columns
        df['traffic_class'] = pd.cut(df['packets'], 
                                   bins=[r[0] for r in ranges] + [float('inf')],
                                   labels=['Low', 'Medium', 'High', 'Very High'])
        
        # Add VFDT-style classification
        df['vfdt_class'] = pd.qcut(df['packets'], q=4, labels=['Q1', 'Q2', 'Q3', 'Q4'])
        
        print("\nTraffic classification summary:")
        print(df['traffic_class'].value_counts())
        
        return df

    def detect_anomalies(self, df):
        """Detect anomalies based on threshold"""
        print("\nDetecting anomalies...")
        # Convert threshold to per-minute basis
        minute_threshold = self.anomaly_threshold * 60
        anomalies = df[df['packets'] > minute_threshold].copy()
        print(f"Found {len(anomalies)} anomalies")
        return anomalies

    def calculate_statistics(self, df):
        """Calculate traffic statistics"""
        print("\nCalculating statistics...")
        stats = {
            'total_packets': df['packets'].sum(),
            'total_bytes': df['bytes'].sum() if 'bytes' in df.columns else 0,
            'avg_packets_per_min': df['packets'].mean(),
            'max_packets_per_min': df['packets'].max(),
            'min_packets_per_min': df['packets'].min(),
            'std_dev_packets': df['packets'].std(),
            'total_minutes': len(df)
        }
        return stats

    def create_visualizations(self, df, anomalies):
        """Create analysis visualizations"""
        print("\nCreating visualizations...")
        plt.figure(figsize=(15, 12))
        
        # Plot 1: Traffic over time with anomalies
        plt.subplot(3, 1, 1)
        plt.plot(df['timestamp'], df['packets'], label='TCP Traffic')
        if not anomalies.empty:
            plt.scatter(anomalies['timestamp'], anomalies['packets'],
                       color='red', label='Anomalies')
        plt.title('TCP Traffic Analysis (LBNL Dataset)')
        plt.xlabel('Time')
        plt.ylabel('Packets/minute')
        plt.legend()
        
        # Plot 2: Traffic distribution by class
        plt.subplot(3, 1, 2)
        df['traffic_class'].value_counts().plot(kind='bar')
        plt.title('Traffic Distribution by Class')
        plt.xlabel('Traffic Class')
        plt.ylabel('Count')
        
        # Plot 3: VFDT classification distribution
        plt.subplot(3, 1, 3)
        df['vfdt_class'].value_counts().plot(kind='bar')
        plt.title('VFDT Classification Distribution')
        plt.xlabel('VFDT Class')
        plt.ylabel('Count')
        
        plt.tight_layout()
        output_path = os.path.join(self.output_dir, 'lbnl_analysis.png')
        plt.savefig(output_path)
        plt.close()
        print(f"Saved visualization to {output_path}")

    def save_results(self, df, stats, anomalies):
        """Save analysis results"""
        print("\nSaving results...")
        output_path = 'outputfile.txt'
        with open(output_path, 'w') as f:
            f.write("=== LBNL TCP Traffic Analysis Results ===\n\n")
            
            f.write("Overall Statistics:\n")
            for key, value in stats.items():
                f.write(f"{key}: {value:,.2f}\n")
            
            f.write("\nTraffic Classification Summary:\n")
            f.write(df['traffic_class'].value_counts().to_string())
            
            f.write("\n\nVFDT Classification Summary:\n")
            f.write(df['vfdt_class'].value_counts().to_string())
            
            f.write(f"\n\nAnomalies Detected: {len(anomalies)}\n")
            if not anomalies.empty:
                f.write("\nTop 5 Anomalous Periods:\n")
                f.write(anomalies.nlargest(5, 'packets').to_string())
        
        print(f"Saved results to {output_path}")

    def analyze_tcp_traffic(self):
        """Main analysis function"""
        print("\nStarting LBNL TCP traffic analysis...")
        
        # Test SiLK functionality
        if not self.test_silk_command():
            print("Error: SiLK tools not properly installed or configured")
            return None
        
        # Get TCP traffic data
        df = self.fetch_tcp_data()
        if df is None or df.empty:
            print("Error: No data available for analysis")
            return None
        
        try:
            # Calculate traffic statistics
            stats = self.calculate_statistics(df)
            
            # Classify traffic
            df = self.classify_traffic(df)
            
            # Detect anomalies
            anomalies = self.detect_anomalies(df)
            
            # Create visualizations
            self.create_visualizations(df, anomalies)
            
            # Save results
            self.save_results(df, stats, anomalies)
            
            return stats
            
        except Exception as e:
            print(f"Error during analysis: {e}")
            traceback.print_exc()
            return None

if __name__ == "__main__":
    print("=== LBNL TCP Traffic Analyzer ===")
    analyzer = LBNLAnalyzer()
    results = analyzer.analyze_tcp_traffic()
    
    if results:
        print("\nAnalysis complete! Check outputfile.txt for detailed results.")
        print("\nKey findings:")
        for key, value in results.items():
            print(f"{key}: {value:,.2f}")
    else:
        print("\nAnalysis failed. Check the error messages above for details.")
