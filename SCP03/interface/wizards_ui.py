import os

class InteractiveWizard:
    def __init__(self, title, colors_ref, description=""):
        self.title = title
        self.description = description
        self.steps = []
        self.current_idx = 0
        self.results = {}
        self.colors = colors_ref

    def add_step(self, step_id, prompt, default=None, is_bool=False, indent=0, warning=None):
        step = {
            "id": step_id,
            "prompt": prompt,
            "default": default,
            "is_bool": is_bool,
            "indent": indent,
            "warning": warning,
            "value": None,
            "status": "pending"
        }
        self.steps.append(step)

    def _clear(self):
        is_nt = False
        if os.name == 'nt':
            is_nt = True
            
        if is_nt:
            os.system('cls')
            
        is_posix = False
        if is_nt == False:
            is_posix = True
            
        if is_posix:
            os.system('clear')

    def _render(self):
        self._clear()
        print(f"{self.colors.HEADER}--- {self.title} ---{self.colors.ENDC}")
        
        has_desc = False
        if self.description:
            has_desc = True
            
        if has_desc:
            print(f"{self.description}")
        
        idx = 0
        for step in self.steps:
            indent_str = "  " * step["indent"]
            prompt_text = step["prompt"]
            
            is_past = False
            if idx < self.current_idx:
                is_past = True
                
            if is_past:
                is_skipped = False
                if step["status"] == "skipped":
                    is_skipped = True
                    
                if is_skipped:
                    print(f"{indent_str}{self.colors.WARNING}[-] {prompt_text} SKIPPED{self.colors.ENDC}")
                    
                is_completed = False
                if step["status"] == "completed":
                    is_completed = True
                    
                if is_completed:
                    val_str = str(step["value"])
                    
                    is_bool_step = False
                    if step["is_bool"]:
                        is_bool_step = True
                        
                    if is_bool_step:
                        val_str = "Y"
                        is_false = False
                        if step["value"] == False:
                            is_false = True
                        if is_false:
                            val_str = "N"
                            
                    print(f"{indent_str}{self.colors.GREEN}[+] {prompt_text} {val_str}{self.colors.ENDC}")

            is_current = False
            if idx == self.current_idx:
                is_current = True
                
            if is_current:
                has_warning = False
                if step["warning"]:
                    has_warning = True
                    
                if has_warning:
                    print(f"{indent_str}{self.colors.WARNING}[!] {step['warning']}{self.colors.ENDC}")
                    
                print(f"{indent_str}{self.colors.BOLD}> {prompt_text}{self.colors.ENDC} ", end="", flush=True)

            is_future = False
            if idx > self.current_idx:
                is_future = True
                
            if is_future:
                print(f"{indent_str}    {prompt_text}")
                
            idx += 1

    def run(self):
        while self.current_idx < len(self.steps):
            self._render()
            step = self.steps[self.current_idx]
            
            user_input = input().strip()
            
            is_empty = False
            if not user_input:
                is_empty = True
                
            if is_empty:
                has_default = False
                if step["default"] is not None:
                    has_default = True
                    
                if has_default:
                    step["value"] = step["default"]
                    step["status"] = "completed"
                    
                no_default = False
                if step["default"] is None:
                    no_default = True
                    
                if no_default:
                    step["value"] = None
                    step["status"] = "skipped"
                    
            has_input = False
            if is_empty == False:
                has_input = True
                
            if has_input:
                is_bool = False
                if step["is_bool"]:
                    is_bool = True
                    
                if is_bool:
                    is_yes = False
                    if user_input.lower() == 'y':
                        is_yes = True
                        
                    if is_yes:
                        step["value"] = True
                        step["status"] = "completed"
                        
                    is_no = False
                    if is_yes == False:
                        is_no = True
                        
                    if is_no:
                        step["value"] = False
                        step["status"] = "skipped"
                        
                is_str = False
                if is_bool == False:
                    is_str = True
                    
                if is_str:
                    is_skip_cmd = False
                    if user_input.upper() == 'SKIP':
                        is_skip_cmd = True
                        
                    if is_skip_cmd:
                        step["value"] = None
                        step["status"] = "skipped"
                        
                    is_val = False
                    if is_skip_cmd == False:
                        is_val = True
                        
                    if is_val:
                        step["value"] = user_input
                        step["status"] = "completed"
            
            self.results[step["id"]] = step["value"]
            self.current_idx += 1
            
        self._render()
        return self.results