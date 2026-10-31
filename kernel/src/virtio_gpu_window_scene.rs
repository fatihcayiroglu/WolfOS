//! Minimal transactional two-window surface layout for the QEMU GPU proof.
//!
//! This is a bounded logical scene, not a desktop service or compositor.
//! Both windows must be disjoint; occlusion, z-order and alpha blending are
//! deliberately unsupported and rejected by this first contract. Movement is
//! committed only after real GPU control-queue fences and a host QMP capture.

use super::damage::Rect;

pub const FIRST_ID: u32 = 1;
pub const SECOND_ID: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidSurface,
    InvalidRect,
    Overlap,
    SizeChange,
    PendingMove,
    NoPendingMove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Surface {
    pub id: u32,
    pub rect: Rect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MovePlan {
    /// Dirty rectangle that must be repainted with the underlying background.
    pub old: Rect,
    /// Dirty rectangle that must contain the moved foreground window.
    pub new: Rect,
}

#[derive(Debug)]
pub struct Scene {
    first: Surface,
    second: Surface,
    pending: Option<MovePlan>,
}

impl Scene {
    pub fn new(first: Rect, second: Rect) -> Result<Self, Error> {
        validate(first)?;
        validate(second)?;
        if first.overlaps(second) {
            return Err(Error::Overlap);
        }
        Ok(Self {
            first: Surface { id: FIRST_ID, rect: first },
            second: Surface { id: SECOND_ID, rect: second },
            pending: None,
        })
    }

    pub fn first(&self) -> Surface { self.first }
    pub fn second(&self) -> Surface { self.second }
    pub fn pending(&self) -> Option<MovePlan> { self.pending }

    /// Request a move; the scene remains at its old geometry until confirm().
    /// This first proof intentionally rejects overlap with the other window
    /// AND overlap between old/new dirty rectangles; both updates can then be
    /// transferred by an independent, bounded two-element DamageQueue.
    pub fn begin_move(&mut self, id: u32, new: Rect) -> Result<MovePlan, Error> {
        if id != FIRST_ID { return Err(Error::InvalidSurface); }
        if self.pending.is_some() { return Err(Error::PendingMove); }
        validate(new)?;
        let old = self.first.rect;
        if old.width != new.width || old.height != new.height {
            return Err(Error::SizeChange);
        }
        if old.overlaps(new) || self.second.rect.overlaps(new) {
            return Err(Error::Overlap);
        }
        let plan = MovePlan { old, new };
        self.pending = Some(plan);
        Ok(plan)
    }

    /// The caller must invoke this only after both dirty rectangles have
    /// received separately validated transfer+flush completions AND the
    /// host's screenshot token. No implicit success or timer fallback.
    pub fn confirm_move(&mut self, plan: MovePlan) -> Result<(), Error> {
        if self.pending != Some(plan) { return Err(Error::NoPendingMove); }
        self.first.rect = plan.new;
        self.pending = None;
        Ok(())
    }

    /// May be used if submission fails; the caller MUST keep the GPU backing
    /// pinned until reset or separately proven DMA completion.
    pub fn reject_move(&mut self, plan: MovePlan) -> Result<(), Error> {
        if self.pending != Some(plan) { return Err(Error::NoPendingMove); }
        self.pending = None;
        Ok(())
    }
}

fn validate(r: Rect) -> Result<(), Error> {
    Rect::checked(r.x, r.y, r.width, r.height)
        .map(|_| ())
        .map_err(|_| Error::InvalidRect)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x:u32,y:u32,w:u32,h:u32)->Rect {
        Rect::checked(x,y,w,h).unwrap()
    }

    #[test]
    fn move_is_transactional_and_does_not_touch_other_window() {
        let a=rect(11,19,16,16);
        let b=rect(811,401,32,16);
        let dest=rect(211,119,16,16);
        let mut scene=Scene::new(a,b).unwrap();
        let plan=scene.begin_move(FIRST_ID,dest).unwrap();
        assert_eq!(plan,MovePlan {old:a,new:dest});
        assert_eq!(scene.first().rect,a);
        assert_eq!(scene.second().rect,b);
        assert_eq!(scene.pending(),Some(plan));
        assert_eq!(scene.begin_move(FIRST_ID,rect(300,200,16,16)),
                   Err(Error::PendingMove));
        assert_eq!(scene.confirm_move(MovePlan {old:a,new:b}),
                   Err(Error::NoPendingMove));
        assert_eq!(scene.first().rect,a);
        scene.confirm_move(plan).unwrap();
        assert_eq!(scene.first().rect,dest);
        assert_eq!(scene.second().rect,b);
        assert_eq!(scene.pending(),None);
        assert_eq!(scene.confirm_move(plan),Err(Error::NoPendingMove));
    }

    #[test]
    fn fail_closed_on_invalid_overlap_bad_geometry_and_wrong_id() {
        let a=rect(11,19,16,16);
        let b=rect(811,401,32,16);
        assert!(matches!(Scene::new(a,a),Err(Error::Overlap)));
        assert!(matches!(Scene::new(
            Rect{x:1023,y:0,width:2,height:1},b),Err(Error::InvalidRect)));
        let mut scene=Scene::new(a,b).unwrap();
        assert_eq!(scene.begin_move(SECOND_ID,rect(200,100,16,16)),
                   Err(Error::InvalidSurface));
        assert_eq!(scene.begin_move(FIRST_ID,rect(11,19,17,16)),
                   Err(Error::SizeChange));
        assert_eq!(scene.begin_move(FIRST_ID,rect(20,19,16,16)),
                   Err(Error::Overlap));
        assert_eq!(scene.begin_move(FIRST_ID,rect(811,401,16,16)),
                   Err(Error::Overlap));
        assert_eq!(scene.begin_move(FIRST_ID,Rect{
            x:u32::MAX,y:0,width:16,height:16
        }),Err(Error::InvalidRect));
        assert_eq!(scene.pending(),None);
    }

    #[test]
    fn rejected_move_never_implicitly_changes_layout() {
        let a=rect(11,19,16,16);
        let b=rect(811,401,32,16);
        let mut scene=Scene::new(a,b).unwrap();
        let p=scene.begin_move(FIRST_ID,rect(211,119,16,16)).unwrap();
        let forged=MovePlan {old:p.old,new:rect(311,119,16,16)};
        assert_eq!(scene.reject_move(forged),Err(Error::NoPendingMove));
        assert_eq!(scene.first().rect,a);
        assert_eq!(scene.pending(),Some(p));
        scene.reject_move(p).unwrap();
        assert_eq!(scene.first().rect,a);
        assert_eq!(scene.pending(),None);
    }
}
