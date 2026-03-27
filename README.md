```
  # Scan an actual benchmark repo                    
  python3 detect.py scan kernelbench-demo/                                         

  # Scan a single file                                             
  python3 detect.py scan kernelbench-demo/src/kernelbench/eval.py                  
                                                                   
  # Use only one detector                            
  python3 detect.py scan kernelbench-demo/ --detector formal
  python3 detect.py scan kernelbench-demo/ --detector llm                          

  # Run regression test against all 50 known issues  
  python3 detect.py test                             

  # Show the issue catalog                           
  python3 detect.py catalog
```
The scan command accepts any file or directory -- point it at a benchmark repo and it automatically finds eval/test/scoring scripts and analyzes them. The test command runs the full comparison of both detectors against the 50-issue catalog (the output you saw earlier with 100%/100%).

Note: the safety_concern false positives on KernelBench files come from the pattern matching proxy/bypass strings that appear in legitimate code contexts. In production, you'd tune the confidence threshold (e.g., --min-confidence 0.8) to filter those out.

