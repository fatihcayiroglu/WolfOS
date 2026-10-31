//! Opaque two-window QEMU scene: clipping by topmost window, no alpha.
//! Logical commits are explicit: the host must have verified real QMP pixels
//! and GPU fences before the caller invokes confirm(). This is NOT a full GUI.

use super::damage::Rect;
use super::window_scene::{FIRST_ID, SECOND_ID, Surface};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRect,
    InvalidId,
    SizeChange,
    IntersectsOld,
    Pending,
    NoPending,
    NoChange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transaction {
    Move { old: Rect, new: Rect },
    Raise { old_top: u32, new_top: u32 },
}

#[derive(Debug)]
pub struct OpaqueScene {
    first: Surface,
    second: Surface,
    top: u32,
    pending: Option<Transaction>,
}

impl OpaqueScene {
    pub fn new(first: Rect, second: Rect) -> Result<Self,Error> {
        checked(first)?;
        checked(second)?;
        if first.overlaps(second) { return Err(Error::IntersectsOld); }
        Ok(Self {
            first: Surface{id:FIRST_ID,rect:first},
            second: Surface{id:SECOND_ID,rect:second},
            top:FIRST_ID,
            pending:None,
        })
    }

    pub fn first(&self)->Surface {self.first}
    pub fn second(&self)->Surface {self.second}
    pub fn top(&self)->u32 {self.top}
    pub fn pending(&self)->Option<Transaction> {self.pending}

    /// An actual on-screen move into the *other surface's* geometry is valid;
    /// this is why an old/new disjoint rule is retained but no second-surface
    /// overlap restriction is imposed.
    pub fn begin_move(&mut self,id:u32,new:Rect)->Result<Transaction,Error>{
        if self.pending.is_some(){return Err(Error::Pending);}
        if id!=FIRST_ID{return Err(Error::InvalidId);}
        checked(new)?;
        let old=self.first.rect;
        if old.width!=new.width || old.height!=new.height {
            return Err(Error::SizeChange);
        }
        if old.overlaps(new){return Err(Error::IntersectsOld);}
        let tx=Transaction::Move{old,new};
        self.pending=Some(tx);
        Ok(tx)
    }

    pub fn begin_raise(&mut self,id:u32)->Result<Transaction,Error>{
        if self.pending.is_some(){return Err(Error::Pending);}
        if id!=FIRST_ID&&id!=SECOND_ID{return Err(Error::InvalidId);}
        if self.top==id{return Err(Error::NoChange);}
        let tx=Transaction::Raise{old_top:self.top,new_top:id};
        self.pending=Some(tx);
        Ok(tx)
    }

    /// Must follow the exact affected-rectangle TRANSFER and FLUSH fenced
    /// replies and a host-verified full-screen QMP RGB capture.
    pub fn confirm(&mut self,tx:Transaction)->Result<(),Error>{
        if self.pending!=Some(tx){return Err(Error::NoPending);}
        match tx{
            Transaction::Move{new,..}=>self.first.rect=new,
            Transaction::Raise{new_top,..}=>self.top=new_top,
        }
        self.pending=None;
        Ok(())
    }

    /// Reject a proposal without inventing a successful screen update.
    /// GPU backing remains pinned until real completions/device reset.
    pub fn reject(&mut self,tx:Transaction)->Result<(),Error>{
        if self.pending!=Some(tx){return Err(Error::NoPending);}
        self.pending=None;
        Ok(())
    }

    /// Which single opaque surface owns the visible pixel after clipping?
    pub fn visible_owner(&self,x:u32,y:u32)->Option<u32>{
        let a=covers(self.first.rect,x,y);
        let b=covers(self.second.rect,x,y);
        match (a,b){
            (true,true)=>Some(self.top),
            (true,false)=>Some(FIRST_ID),
            (false,true)=>Some(SECOND_ID),
            (false,false)=>None,
        }
    }
}

fn checked(rect:Rect)->Result<(),Error>{
    Rect::checked(rect.x,rect.y,rect.width,rect.height)
        .map(|_|()).map_err(|_|Error::InvalidRect)
}

fn covers(r:Rect,x:u32,y:u32)->bool {
    x>=r.x&&x<r.x+r.width&&y>=r.y&&y<r.y+r.height
}

#[cfg(test)]
mod tests{
    use super::*;
    fn rect(x:u32,y:u32,w:u32,h:u32)->Rect{
        Rect::checked(x,y,w,h).unwrap()
    }

    #[test]
    fn overlapping_surface_move_commits_only_with_explicit_ack(){
        let old=rect(11,19,16,16);
        let fixed=rect(811,401,32,16);
        let new=rect(819,401,16,16);
        let mut s=OpaqueScene::new(old,fixed).unwrap();
        let tx=s.begin_move(FIRST_ID,new).unwrap();
        assert_eq!(s.first().rect,old);
        assert_eq!(s.top(),FIRST_ID);
        assert_eq!(s.begin_raise(SECOND_ID),Err(Error::Pending));
        assert_eq!(s.visible_owner(820,402),Some(SECOND_ID));
        assert_eq!(s.confirm(Transaction::Move{old,new:rect(300,150,16,16)}),
                   Err(Error::NoPending));
        s.confirm(tx).unwrap();
        assert_eq!(s.first().rect,new);
        assert_eq!(s.visible_owner(820,402),Some(FIRST_ID));
        assert_eq!(s.visible_owner(812,402),Some(SECOND_ID));
        assert_eq!(s.visible_owner(100,100),None);
        assert_eq!(s.confirm(tx),Err(Error::NoPending));
    }

    #[test]
    fn raising_lower_window_controls_opaque_clip_and_is_transactional(){
        let mut s=OpaqueScene::new(rect(11,19,16,16),
                                   rect(811,401,32,16)).unwrap();
        let moved=s.begin_move(FIRST_ID,rect(819,401,16,16)).unwrap();
        s.confirm(moved).unwrap();
        let lower=s.begin_raise(SECOND_ID).unwrap();
        assert_eq!(s.visible_owner(820,402),Some(FIRST_ID));
        assert_eq!(s.begin_raise(FIRST_ID),Err(Error::Pending));
        s.confirm(lower).unwrap();
        assert_eq!(s.visible_owner(820,402),Some(SECOND_ID));
        assert_eq!(s.begin_raise(SECOND_ID),Err(Error::NoChange));
        let raise=s.begin_raise(FIRST_ID).unwrap();
        assert_eq!(s.visible_owner(820,402),Some(SECOND_ID));
        s.confirm(raise).unwrap();
        assert_eq!(s.visible_owner(820,402),Some(FIRST_ID));
    }

    #[test]
    fn bad_moves_and_wrong_receipts_do_not_mutate_layout(){
        let mut s=OpaqueScene::new(rect(11,19,16,16),
                                   rect(811,401,32,16)).unwrap();
        assert_eq!(s.begin_move(SECOND_ID,rect(200,150,16,16)),
                   Err(Error::InvalidId));
        assert_eq!(s.begin_move(FIRST_ID,rect(211,119,15,16)),
                   Err(Error::SizeChange));
        assert_eq!(s.begin_move(FIRST_ID,rect(15,22,16,16)),
                   Err(Error::IntersectsOld));
        assert_eq!(s.begin_move(FIRST_ID,Rect{
            x:u32::MAX,y:0,width:16,height:16,
        }),Err(Error::InvalidRect));
        assert_eq!(s.begin_raise(3),Err(Error::InvalidId));
        assert_eq!(s.begin_raise(FIRST_ID),Err(Error::NoChange));
        let tx=s.begin_move(FIRST_ID,rect(819,401,16,16)).unwrap();
        let counterfeit=Transaction::Move{
            old:rect(11,19,16,16),new:rect(211,119,16,16),
        };
        assert_eq!(s.reject(counterfeit),Err(Error::NoPending));
        assert_eq!(s.first().rect,rect(11,19,16,16));
        s.reject(tx).unwrap();
        assert_eq!(s.pending(),None);
        assert_eq!(s.first().rect,rect(11,19,16,16));
        assert!(matches!(OpaqueScene::new(
            rect(800,401,16,16),rect(811,401,32,16)),Err(Error::IntersectsOld)));
    }
}
